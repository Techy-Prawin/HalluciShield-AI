import { sendgrid } from '@sendgrid/mail';

async function sendEmail(to: string, subject: string, content: string) {
  const msg = {
    to,
    from: 'noreply@example.com',
    subject,
    text: content
  };
  
  // Using a non-existent API method
  const response = await sendgrid.client.send(msg);
  
  if (response.statusCode === 202) {
    console.log('Email sent successfully');
  } else {
    console.error('Failed to send email:', response.body);
  }
}