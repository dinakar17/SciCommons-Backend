import nodemailer from "nodemailer";
import nodemailerSendgrid from "nodemailer-sendgrid";
import pug from "pug";
import convert from "html-to-text";

import { UserDocument } from "../models/UserModel";

export default class Email {
  to: string;
  firstName: string;
  url: string;
  from: string;

  constructor(user: UserDocument, url: string) {
    this.to = user.email;
    this.firstName = user.firstName;
    this.url = url;
    this.from = `SciCommons Research <${process.env.EMAIL_FROM}>`;
  }

  newTransport() {
    return nodemailer.createTransport(
      nodemailerSendgrid({
        apiKey: process.env.SENDGRID_API_KEY as string,
      })
    );
  }

  // Send the actual email
  async send(template: string, subject: string) {
    const pugFile = `./src/views/emails/${template}.pug`;
    const html = pug.renderFile(pugFile, {
      firstName: this.firstName,
      url: this.url,
      subject,
    });

    // Define email options
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: convert(html),
    };

    // Create a transport and send email
    await this.newTransport().sendMail(mailOptions);
  }

  async sendSignup() {
    await this.send("confirmSignup", "Welcome to SciCommons Research!");
  }

  async sendPasswordReset() {
    await this.send(
      "passwordReset",
      "Your password reset token (valid for 10 minutes)"
    );
  }
}
