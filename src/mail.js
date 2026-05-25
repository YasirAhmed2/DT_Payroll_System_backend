import nodemailer from 'nodemailer';

function normalizeConfiguredEmail(value) {
	const email = String(value ?? '').trim().toLowerCase();
	if (!email) {
		return '';
	}
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		throw new Error('Invalid OTP recipient email configured in the environment.');
	}
	return email;
}

export function getOtpRecipientEmail() {
	const recipient = normalizeConfiguredEmail(process.env.OTP_RECIPIENT_EMAIL || process.env.EMAIL_USER);
	if (!recipient) {
		throw new Error('Missing OTP recipient email. Set OTP_RECIPIENT_EMAIL or EMAIL_USER in the environment.');
	}
	return recipient;
}

function getTransport() {
	const host = process.env.SMTP_HOST || process.env.BREVO_SMTP_HOST || (process.env.BREVO_SMTP_USER && process.env.BREVO_SMTP_PASS ? 'smtp-relay.brevo.com' : '');
	if (!host) {
		return null;
	}

	const authUser = process.env.SMTP_USER || process.env.BREVO_SMTP_USER;
	const authPass = process.env.SMTP_PASSWORD || process.env.BREVO_SMTP_PASS || '';

	return nodemailer.createTransport({
		host,
		port: Number(process.env.SMTP_PORT || process.env.BREVO_SMTP_PORT || 587),
		secure: String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true',
		auth: authUser
			? {
				user: authUser,
				pass: authPass,
			}
			: undefined,
	});
}

export async function sendSignupOtpEmail({ to, otp, purpose }) {
	const recipient = getOtpRecipientEmail();
	const from = process.env.EMAIL_FROM || process.env.EMAIL_USER || 'no-reply@payroll.local';
	const transport = getTransport();
	const subject = `${purpose} verification code`;
	const text = `Your verification code is ${otp}. It expires in 10 minutes.`;

	if (!transport) {
		// Dev fallback: keep the flow usable without SMTP, but make the OTP visible in server logs.
		// eslint-disable-next-line no-console
		console.log(`[OTP:${purpose}] send to ${recipient} (requested for ${to}): ${otp}`);
		return { delivery: 'console' };
	}

	await transport.sendMail({
		from,
		to: recipient,
		subject,
		text,
	});

	return { delivery: 'email' };
}