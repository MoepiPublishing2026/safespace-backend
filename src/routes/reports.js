const express = require('express');
const router = express.Router();
const db = require('../database');
const { sendReportConfirmation, sendAdminNewReportNotification } = require('../utils/mailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const { clean, cleanParam, isMaliciousInput } = require('../utils/sanitizeInput');

/* -------------------------------
   MULTER (UPDATED - MULTIPLE FILES)
--------------------------------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadsDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const cleanName = file.originalname.replace(/[^A-Za-z0-9.\-_]/g, '');
    cb(null, `report-${Date.now()}-${cleanName}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

/* -------------------------------
   CASE NUMBER GENERATION
--------------------------------- */
const abuseTypeMap = { 1: 'BU', 2: 'SA', 3: 'SX', 4: 'TP', 5: 'WP', 6: 'VL' };

const generateCaseNumber = async (abuse_type_id) => {
  const prefix = abuseTypeMap[abuse_type_id] || 'XX';
  const [rows] = await db.execute(
    'SELECT MAX(id) AS max_id FROM reports WHERE abuse_type_id = ?',
    [abuse_type_id]
  );

  const nextNum = (rows[0].max_id || 0) + 1;
  const formatted = nextNum.toString().padStart(4, '0');

  const now = new Date();
  const day = String(now.getDate()).padStart(2, '0');
  const month = String(now.getMonth() + 1).padStart(2, '0');

  return `${prefix}${formatted}${day}${month}`;
};

/* -------------------------------
   CREATE REPORT (FIXED FOR MULTIPLE FILES)
--------------------------------- */
router.post('/', upload.array('files', 10), async (req, res) => {
  try {
    const body = Object.fromEntries(
      Object.entries(req.body).map(([k, v]) => [k, v ? clean(v) : null])
    );

    const badField = Object.entries(body).find(([_, v]) => isMaliciousInput(v))?.[0];
    if (badField) {
      return res.status(403).json({ message: `Malicious input detected in field: ${badField}` });
    }

    const {
      abuse_type_id, subtype_id, description, reporter_email,
      phone_number, full_name, age, location, grade, school_name,
      status = "Pending", is_anonymous = 0
    } = body;

    if (!abuse_type_id || !phone_number || !age || !location || !school_name) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    // --- School lookup ---
    const [schoolRows] = await db.execute(
      "SELECT school_id, district_id, province_id FROM schools WHERE school_name = ?",
      [school_name]
    );

    if (!schoolRows.length) {
      return res.status(400).json({ message: "Invalid school name" });
    }

    const { school_id, district_id, province_id } = schoolRows[0];

    // --- MULTIPLE FILE HANDLING ---
    const file_paths = req.files
      ? req.files.map(file => `/uploads/${file.filename}`)
      : [];

    // --- Generate case number ---
    const case_number = await generateCaseNumber(abuse_type_id);

    // --- INSERT ---
    const query = `
      INSERT INTO reports
      (abuse_type_id, subtype_id, description, reporter_email, phone_number,
       full_name, age, location, grade, school_name, school_id, district_id, province_id,
       case_number, status, is_anonymous, image_path, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
    `;

    const values = [
      abuse_type_id,
      subtype_id ?? null,
      description,
      reporter_email ?? null,
      phone_number,
      full_name ?? null,
      age,
      location,
      grade ?? null,
      school_name,
      school_id,
      district_id,
      province_id,
      case_number,
      status,
      is_anonymous,
      JSON.stringify(file_paths) // store multiple files
    ];

    const [result] = await db.execute(query, values);

    // --- Emails ---
    if (reporter_email) {
      sendReportConfirmation(reporter_email, full_name, case_number);
    }

    const [admins] = await db.execute(
      `SELECT email, name FROM users WHERE role = 'school' AND school_name = ?`,
      [school_name]
    );

    const submittedAt = new Date().toLocaleString();

    admins.forEach(a => {
      sendAdminNewReportNotification(
        a.email,
        full_name,
        case_number,
        location,
        submittedAt
      );
    });

    res.status(201).json({
      message: "Report created successfully",
      reportId: result.insertId,
      case_number
    });

  } catch (err) {
    console.error("Report error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
/* -------------------------------
   GET ABUSE TYPES
--------------------------------- */
router.get('/abuse-types', async (req, res) => {
  try {
    const [results] = await db.execute(
      "SELECT id, type_name AS abuse_type_name FROM abuse_types"
    );

    res.json(results);
  } catch (err) {
    console.error("GET ABUSE TYPES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* -------------------------------
   GET SUBTYPES
--------------------------------- */
router.get('/subtypes/:abuse_type_id', async (req, res) => {
  try {
    const abuse_type_id = cleanParam(req.params.abuse_type_id);
    if (isMaliciousInput(abuse_type_id)) {
      return res.status(403).json({ message: "Malicious input detected" });
    }

    const [results] = await db.execute(
      "SELECT id, sub_type_name FROM subtypes WHERE abuse_type_id = ?",
      [abuse_type_id]
    );

    res.json(results);

  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

/* -------------------------------
   GET REPORT BY CASE NUMBER
--------------------------------- */
router.get('/case/:case_number', async (req, res) => {
  try {
    const case_number = cleanParam(decodeURIComponent(req.params.case_number));

    const [results] = await db.execute(
      `SELECT r.*,
              a.type_name AS abuse_type,
              s.sub_type_name AS subtype
       FROM reports r
       LEFT JOIN abuse_types a ON r.abuse_type_id = a.id
       LEFT JOIN subtypes s ON r.subtype_id = s.id
       WHERE r.case_number = ?`,
      [case_number]
    );

    if (!results.length) {
      return res.status(404).json({ message: "Reference Number not found" });
    }

    res.json(results[0]); // frontend now gets abuse_type and subtype
  } catch (err) {
    console.error("GET CASE ERROR:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

/* -------------------------------
   UPDATE REPORT (MULTIPLE FILES SUPPORT)
--------------------------------- */
router.put('/:case_number', upload.array('files', 10), async (req, res) => {
  try {
    const case_number = cleanParam(req.params.case_number);

    if (isMaliciousInput(case_number)) {
      return res.status(403).json({ message: "Malicious input detected" });
    }

    const updates = {};

    const allowedFields = [
      "description",
      "phone_number",
      "full_name",
      "age",
      "location",
      "school_name",
      "status",
      "subtype_id",
      "grade",
      "is_anonymous"
    ];

    for (const field of allowedFields) {
      const value = req.body[field];
    
      if (value === undefined) continue;
    
      // 🔥 SPECIAL LOGIC FOR FULL NAME
      if (field === "full_name") {
        if (!value || value.trim() === "") {
          updates.full_name = null;        
          updates.is_anonymous = 1;        
        } else {
          updates.full_name = clean(value);
          updates.is_anonymous = 0;       
        }
      } else if (field !== "is_anonymous") {
        if (value !== undefined) {
          updates[field] = value === '' ? '' : clean(value);
        }
      }
    }

    // --- Handle files correctly ---
    let existingFiles = [];
    if (req.body.existingFiles) {
      try {
        existingFiles = JSON.parse(req.body.existingFiles);
      } catch (e) {
        console.warn("Failed to parse existingFiles:", e);
      }
    }

    const newFiles = req.files?.map(f => `/uploads/${f.filename}`) || [];

    // Save only kept files + newly uploaded files
    if (existingFiles.length || newFiles.length) {
      updates.image_path = JSON.stringify([...existingFiles, ...newFiles]);
    }

    if (!Object.keys(updates).length) {
      return res.status(400).json({ message: "No valid fields provided" });
    }

    const fields = Object.keys(updates)
      .map(key => `${key} = ?`)
      .join(', ');

    const values = [...Object.values(updates), case_number];

    const query = `UPDATE reports SET ${fields}, updated_at = NOW() WHERE case_number = ?`;

    const [result] = await db.execute(query, values);

    if (!result.affectedRows) {
      return res.status(404).json({ message: "Report not found" });
    }

    res.json({
      message: "Report updated successfully",
      case_number,
      updated_fields: Object.keys(updates)
    });

  } catch (err) {
    console.error("Update error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;