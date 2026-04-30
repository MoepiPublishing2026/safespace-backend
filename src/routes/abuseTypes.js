const express = require('express');
const router = express.Router();
const db = require('../database'); // your promise pool

router.get('/', async (req, res) => {
  try {
   const [results] = await db.query(
  'SELECT * FROM abuse_types ORDER BY type_name ASC'
);
// promise API
    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

router.get('/test-db', async (req, res) => {
  try {
    const [rows] = await db.query("SELECT 1 AS test");
    console.log("✅ DB TEST SUCCESS:", rows);
    res.json(rows);
  } catch (err) {
    console.error("❌ DB TEST FAILED:", err);
    res.status(500).json({
      message: err.message,
      code: err.code
    });
  }
});

module.exports = router;
