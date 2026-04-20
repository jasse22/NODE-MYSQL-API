import config from '../config.json';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Op } from 'sequelize';
import sendEmail from '../_helpers/send-email';
import db from '../_helpers/db';
import Role from '../_helpers/role';

export default {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({ email, password, ipAddress }: any) {
    const account = await db.Account.scope('withHash').findOne({ where: { email } });
    
    if (!account || !(await bcrypt.compare(password, account.passwordHash))) {
        throw 'Email or password is incorrect';
    }
    
    if (!account.isVerified) {
        throw 'Account not verified';
    }
    
    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);
    await refreshToken.save();
    
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }: any) {
    const refreshToken = await getRefreshToken(token);
    const account = await refreshToken.getAccount();
    
    // Replace old refresh token with a new one (Token Rotation)
    const newRefreshToken = generateRefreshToken(account, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();
    
    const jwtToken = generateJwtToken(account);
    
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

async function revokeToken({ token, ipAddress }: any) {
    const refreshToken = await getRefreshToken(token);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}

async function register(params: any, origin: string) {
    // Validate
    if (await db.Account.findOne({ where: { email: params.email } })) {
        throw `Email ${params.email} is already registered`;
    }
    
    // Create account
    const account = new db.Account(params);
    account.verificationToken = randomTokenString();
    account.passwordHash = await hash(params.password);
    account.role = Role.User;
    await account.save();
    
    // Send email
    await sendVerificationEmail(account, origin);
}

async function verifyEmail({ token }: any) {
    const account = await db.Account.findOne({ where: { verificationToken: token } });
    if (!account) throw 'Verification failed';
    
    account.verified = Date.now();
    account.verificationToken = null;
    await account.save();
}

async function forgotPassword({ email }: any, origin: string) {
    const account = await db.Account.findOne({ where: { email } });
    if (!account) return;
    
    // Create reset token
    account.resetToken = randomTokenString();
    account.resetTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await account.save();
    
    // Send email
    await sendPasswordResetEmail(account, origin);
}

async function validateResetToken({ token }: any) {
    const account = await db.Account.findOne({
        where: {
            resetToken: token,
            resetTokenExpires: { [Op.gt]: Date.now() }
        }
    });
    if (!account) throw 'Invalid token';
    return account;
}

async function resetPassword({ token, password }: any) {
    const account = await validateResetToken({ token });
    account.passwordHash = await hash(password);
    account.passwordReset = Date.now();
    account.resetToken = null;
    await account.save();
}

async function getAll() {
    const accounts = await db.Account.findAll();
    return accounts.map((x: any) => basicDetails(x));
}

async function getById(id: any) {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function create(params: any) {
    if (await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already registered';
    }
    
    const account = new db.Account(params);
    account.verified = Date.now();
    account.passwordHash = await hash(params.password);
    await account.save();
    
    return basicDetails(account);
}

async function update(id: any, params: any) {
    const account = await getAccount(id);
    
    // Check email uniqueness
    if (params.email && account.email !== params.email && 
        await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already taken';
    }
    
    // Hash password if provided
    if (params.password) {
        params.passwordHash = await hash(params.password);
    }
    
    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();
    
    return basicDetails(account);
}

async function _delete(id: any) {
    const account = await getAccount(id);
    await account.destroy();
}

// Helper Functions
async function getAccount(id: any) {
    const account = await db.Account.findByPk(id);
    if (!account) throw 'Account not found';
    return account;
}

async function getRefreshToken(token: string) {
    const refreshToken = await db.RefreshToken.findOne({ where: { token } });
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

function hash(password: string) {
    return bcrypt.hash(password, 10);
}

function generateJwtToken(account: any) {
    return jwt.sign({ sub: account.id, id: account.id }, config.secret, { expiresIn: '15m' });
}

function generateRefreshToken(account: any, ipAddress: string) {
    return new db.RefreshToken({
        accountId: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account: any) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

async function sendVerificationEmail(account: any, origin: string) {
    let message;
    if (origin) {
        message = `<p>Please use the below token to verify your email address:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }
    
    await sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Verify Email',
        html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`
    });
}

async function sendPasswordResetEmail(account: any, origin: string) {
    let message;
    if (origin) {
        message = `<p>Please use the below token to reset your password:</p>
                   <p><code>${account.resetToken}</code></p>`;
    } else {
        message = `<p>Please use the below token to reset your password:</p>
                   <p><code>${account.resetToken}</code></p>`;
    }
    
    await sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}