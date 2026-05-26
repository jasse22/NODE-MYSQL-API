"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_json_1 = __importDefault(require("../config.json"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const crypto_1 = __importDefault(require("crypto"));
const sequelize_1 = require("sequelize");
const send_email_1 = __importDefault(require("../_helpers/send-email"));
const db_1 = __importDefault(require("../_helpers/db"));
const role_1 = __importDefault(require("../_helpers/role"));
exports.default = {
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
async function authenticate({ email, password, ipAddress }) {
    const account = await db_1.default.Account.scope('withHash').findOne({ where: { email } });
    if (!account || !(await bcryptjs_1.default.compare(password, account.passwordHash))) {
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
async function refreshToken({ token, ipAddress }) {
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
async function revokeToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}
async function register(params, origin) {
    // Validate
    if (await db_1.default.Account.findOne({ where: { email: params.email } })) {
        throw `Email ${params.email} is already registered`;
    }
    // Create account
    const account = new db_1.default.Account(params);
    account.verificationToken = randomTokenString();
    account.passwordHash = await hash(params.password);
    account.role = role_1.default.User;
    await account.save();
    // Send email
    await sendVerificationEmail(account, origin);
}
async function verifyEmail({ token }) {
    const account = await db_1.default.Account.findOne({ where: { verificationToken: token } });
    if (!account)
        throw 'Verification failed';
    account.verified = Date.now();
    account.verificationToken = null;
    await account.save();
}
async function forgotPassword({ email }, origin) {
    const account = await db_1.default.Account.findOne({ where: { email } });
    if (!account)
        return;
    // Create reset token
    account.resetToken = randomTokenString();
    account.resetTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await account.save();
    // Send email
    await sendPasswordResetEmail(account, origin);
}
async function validateResetToken({ token }) {
    const account = await db_1.default.Account.findOne({
        where: {
            resetToken: token,
            resetTokenExpires: { [sequelize_1.Op.gt]: Date.now() }
        }
    });
    if (!account)
        throw 'Invalid token';
    return account;
}
async function resetPassword({ token, password }) {
    const account = await validateResetToken({ token });
    account.passwordHash = await hash(password);
    account.passwordReset = Date.now();
    account.resetToken = null;
    await account.save();
}
async function getAll() {
    const accounts = await db_1.default.Account.findAll();
    return accounts.map((x) => basicDetails(x));
}
async function getById(id) {
    const account = await getAccount(id);
    return basicDetails(account);
}
async function create(params) {
    if (await db_1.default.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already registered';
    }
    const account = new db_1.default.Account(params);
    account.verified = Date.now();
    account.passwordHash = await hash(params.password);
    await account.save();
    return basicDetails(account);
}
async function update(id, params) {
    const account = await getAccount(id);
    // Check email uniqueness
    if (params.email && account.email !== params.email &&
        await db_1.default.Account.findOne({ where: { email: params.email } })) {
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
async function _delete(id) {
    const account = await getAccount(id);
    await account.destroy();
}
// Helper Functions
async function getAccount(id) {
    const account = await db_1.default.Account.findByPk(id);
    if (!account)
        throw 'Account not found';
    return account;
}
async function getRefreshToken(token) {
    const refreshToken = await db_1.default.RefreshToken.findOne({ where: { token } });
    if (!refreshToken || !refreshToken.isActive)
        throw 'Invalid token';
    return refreshToken;
}
function hash(password) {
    return bcryptjs_1.default.hash(password, 10);
}
function generateJwtToken(account) {
    return jsonwebtoken_1.default.sign({ sub: account.id, id: account.id }, config_json_1.default.secret, { expiresIn: '15m' });
}
function generateRefreshToken(account, ipAddress) {
    return new db_1.default.RefreshToken({
        accountId: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        createdByIp: ipAddress
    });
}
function randomTokenString() {
    return crypto_1.default.randomBytes(40).toString('hex');
}
function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}
async function sendVerificationEmail(account, origin) {
    let message;
    if (origin) {
        message = `<p>Please use the below token to verify your email address:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }
    else {
        message = `<p>Please use the below token to verify your email address:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }
    await (0, send_email_1.default)({
        to: account.email,
        subject: 'Sign-up Verification API - Verify Email',
        html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`
    });
}
async function sendPasswordResetEmail(account, origin) {
    let message;
    if (origin) {
        message = `<p>Please use the below token to reset your password:</p>
                   <p><code>${account.resetToken}</code></p>`;
    }
    else {
        message = `<p>Please use the below token to reset your password:</p>
                   <p><code>${account.resetToken}</code></p>`;
    }
    await (0, send_email_1.default)({
        to: account.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}
