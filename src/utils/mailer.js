require('dotenv').config();
const nodemailer = require('nodemailer');

// Create transporter for cPanel email
const transporter = nodemailer.createTransport({
  host: 'mail.teketesafespace.co.za',
  port: 465,
  secure: true, // true for port 465
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  authMethod: 'LOGIN',
  tls: {
    rejectUnauthorized: false
  }
});



// ✅ Report confirmation email 
function sendReportConfirmation(to, fullName, caseNumber) {
  const mailOptions = {
    from: `"Tekete SafeSpace" <${process.env.EMAIL_USER}>`,
    to,
    subject: 'Your Case Number Confirmation',
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Incident Report Confirmation</title>
      </head>

      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">

          <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">

              <h2 style="color: #4CAF50;">
                  Thank You for Your Report
              </h2>

              <p>
                  This email is to confirm that we have received your incident report.
                  Your unique case number is:
              </p>

              <div style="background-color: #f4f4f4; padding: 15px; text-align: center; border-radius: 5px; margin: 20px 0;">

                  <h3 style="margin: 0; color: #007bff; font-size: 24px;">
                      ${caseNumber}
                  </h3>

              </div>

              <p>
                  Please keep this number safe for future reference.
                  We will use it to track your case and provide updates.
              </p>

              <p>
                  We appreciate you taking the time to report this incident.
                  We are committed to ensuring the safety and well-being of our community.
              </p>

              <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">

              <p style="font-size: 12px; color: #888;">
                  This is an automated email. Please do not reply.
              </p>

          </div>

          <footer style="
              background-color: #d3d3d3;
              color: black;
              text-align: center;
              padding: 1rem 0;
              position: relative;
              bottom: 0;
              width: 100%;
              margin-top: 3rem;
          ">
              <div>
                  <p style="margin: 0;">
                      © ${new Date().getFullYear()} Tekete Safe Space from Moepi Publishing
                  </p>
              </div>
          </footer>

      </body>
      </html>
    `
  };

  return transporter.sendMail(mailOptions);
}

function sendReportUpdateNotification(to, caseNumber, status, message) {
  const mailOptions = {
    from: `"Tekete SafeSpace" <${process.env.EMAIL_USER}>`,
    to,
    subject: `Case Update - ${caseNumber}`,
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Incident Report Update</title>
      </head>

      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">

          <div style="max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">

              <h2 style="color: #4CAF50;">
                  Your Report Has Been Updated
              </h2>

              <p>
                  This email is to inform you that there has been an update
                  to your incident report.
              </p>

              <p>
                  Your case number is:
              </p>

              <div style="background-color: #f4f4f4; padding: 15px; text-align: center; border-radius: 5px; margin: 20px 0;">

                  <h3 style="margin: 0; color: #007bff; font-size: 24px;">
                      ${caseNumber}
                  </h3>

              </div>

              <p>
                  <strong>Status:</strong>
                  <span style="color: #4CAF50; font-weight: bold;">
                      ${status}
                  </span>
              </p>

              ${
                message
                  ? `
                    <p>
                        <strong>Update:</strong>
                    </p>

                    <p>
                        ${message}
                    </p>
                  `
                  : ''
              }

              <p>
                  Please keep your case number safe for future reference.
                  We will use it to track your case and provide further updates.
              </p>

              <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">

              <p style="font-size: 12px; color: #888;">
                  This is an automated email. Please do not reply.
              </p>

          </div>

          <footer style="
              background-color: #d3d3d3;
              color: black;
              text-align: center;
              padding: 1rem 0;
              position: relative;
              bottom: 0;
              width: 100%;
              margin-top: 3rem;
          ">
              <div>
                  <p style="margin: 0;">
                      © ${new Date().getFullYear()} Tekete Safe Space from Moepi Publishing
                  </p>
              </div>
          </footer>

      </body>
      </html>
    `
  };

  return transporter.sendMail(mailOptions);
}
// ✅ Notify Admin of new report 
function sendAdminNewReportNotification(adminEmail, fullName, caseNumber, location, submittedAt) {
  const mailOptions = {
    from: `"Tekete SafeSpace" <${process.env.EMAIL_USER}>`,
    to: adminEmail,
    subject: `New Report Submitted: ${caseNumber}`,
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Report Submitted</title>
        <style>
          body {
            background-color: #f6f8fb;
            font-family: 'Segoe UI', Roboto, Arial, sans-serif;
            margin: 0;
            padding: 0;
            color: #1f2937;
          }
          .container {
            max-width: 600px;
            background-color: #ffffff;
            margin: 40px auto;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
          }
          .header {
            background-color: #f1f3f6;
            text-align: center;
            padding: 15px;
            font-weight: bold;
            color: #1f2937;
            font-size: 20px;
          }
          .content {
            padding: 30px 40px;
            color: #374151;
            font-size: 15px;
            line-height: 1.6;
          }
          .content h2 {
            color: #111827;
            margin-bottom: 10px;
          }
          .content p {
            margin: 8px 0;
          }
          .label {
            font-weight: 600;
            color: #111827;
          }
          .button {
            display: inline-block;
            background-color: #1f2937;
            color: #ffffff !important;
            text-decoration: none;
            font-weight: 600;
            padding: 12px 28px;
            border-radius: 6px;
            margin: 25px 0;
          }
          .footer {
            background-color: #f9fafb;
            text-align: left;
            padding: 20px 40px;
            font-size: 14px;
            color: #6b7280;
          }
          @media (max-width: 480px) {
            .content {
              padding: 20px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
           Tekete SafeSpace
          </div>
          <div class="content">
            <h2>New Report Submitted</h2>
            <p>A reporter has submitted a <strong>new report</strong>.</p>
            
            <p><span class="label">Case Number:</span> ${caseNumber}</p>
            <p><span class="label">Location:</span> ${location || 'Not provided'}</p>
            <p><span class="label">Submitted At:</span> ${submittedAt || new Date().toLocaleString()}</p>
            <p><span class="label">Reporter:</span> ${fullName || 'Anonymous'}</p>

            <a href="https://staging.teketesafespace.co.za/school-admin" class="button">View Report</a>
          </div>
          <div class="footer">
            <p>Thanks,<br>Tekete SafeSpace</p>
          </div>
        </div>
      </body>
      </html>
    `
  };

  return transporter.sendMail(mailOptions);
}


module.exports = { 
  sendReportConfirmation, 
  sendReportUpdateNotification,
  sendAdminNewReportNotification 
};
