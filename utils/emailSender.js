import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'gmail', // or your email provider
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD
  }
});

export async function sendEmail(to, subject, text, html) {
  try {
    await transporter.sendMail({
      from: `"InstantBackup" <${process.env.EMAIL_USERNAME}>`,
      to,
      subject,
      text,
      html
    });
    return { success: true };
  } catch (error) {
    console.error('Error sending email:', error);
    return { success: false, error };
  }
}