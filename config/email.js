const nodemailer = require('nodemailer');

// Function to fetch user email settings
const getUserEmailSettings = async (userId) => {
  try {
    // Fetch user's email configuration from the database
    const result = await query(
      'SELECT email, password, smtp_host, smtp_port FROM user_email_config WHERE user_id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      throw new Error('No email configuration found');
    }

    return result.rows[0];  // Return the email configuration
  } catch (error) {
    console.error('❌ Error fetching email settings:', error);
    throw new Error('Error fetching email configuration');
  }
};

// Send email using dynamic configuration
const sendEmail = async (userId, subject, text) => {
  try {
    const { email, password, smtp_host, smtp_port } = await getUserEmailSettings(userId);

    // Create a transporter using the dynamic email settings
    const transporter = nodemailer.createTransport({
      host: smtp_host, 
      port: smtp_port,
      auth: {
        user: email, // User's email
        pass: password, // User's email password
      },
    });

    const mailOptions = {
      from: email, // Sender address
      to: email, // Recipient's address (can be dynamic)
      subject: subject, // Subject
      text: text, // Body content
    };

    // Send email
    await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to: ${email}`);

    return { success: true, message: 'Email sent successfully' };
  } catch (error) {
    console.error('❌ Error sending email:', error);
    return { success: false, message: 'Error occurred while sending email' };
  }
};

module.exports = {
  sendEmail,
};
