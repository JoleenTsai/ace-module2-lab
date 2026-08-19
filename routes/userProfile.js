/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { AllHtmlEntities as Entities } from 'html-entities';
import config from 'config';
import fs from 'node:fs/promises';
import * as challengeUtils from '../lib/challengeUtils';
import { themes } from '../views/themes/themes';
import { challenges } from '../data/datacache';
import * as security from '../lib/insecurity';
import { UserModel } from '../models/user';
import * as utils from '../lib/utils';
const entities = new Entities();
function favicon() {
    return utils.extractFilename(config.get('application.favicon'));
}
function isSafeExpression(code) {
    // Regexes to match single and double quoted string literals (handling escaped quotes/backslashes)
    const singleQuoteRegex = /'([^'\\]|\\.)*'/g;
    const doubleQuoteRegex = /"([^"\\]|\\.)*"/g;
    // Remove all single and double quoted string literals
    const remainder = code
        .replace(singleQuoteRegex, '')
        .replace(doubleQuoteRegex, '');
    // The remaining characters must only be digits, basic arithmetic operators, or whitespace
    // Hyphen is at the end, slash is escaped, \s is whitespace
    return /^[0-9+*/\s-]*$/.test(remainder);
}
export function getUserProfile() {
    return async (req, res, next) => {
        let template;
        try {
            template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' });
        }
        catch (err) {
            next(err);
            return;
        }
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
        if (!loggedInUser) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            return;
        }
        let user;
        try {
            user = await UserModel.findByPk(loggedInUser.data.id);
        }
        catch (error) {
            next(error);
            return;
        }
        if (!user) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            return;
        }
        let username = user.username;
        if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
            req.app.locals.abused_ssti_bug = true;
            const code = username?.substring(2, username.length - 1);
            try {
                if (!code) {
                    throw new Error('Username is null');
                }
                if (!isSafeExpression(code)) {
                    throw new Error('Unsafe expression');
                }
                username = eval(code); // eslint-disable-line no-eval
            }
            catch (err) {
                username = '\\' + username;
            }
        }
        else {
            username = '\\' + username;
        }
        const themeKey = config.get('application.theme');
        const theme = themes[themeKey] || themes['bluegrey-lightgreen'];
        if (username) {
            template = template.replace(/_username_/g, username);
        }
        template = template.replace(/_emailHash_/g, security.hash(user?.email));
        template = template.replace(/_title_/g, entities.encode(config.get('application.name')));
        template = template.replace(/_favicon_/g, favicon());
        template = template.replace(/_bgColor_/g, theme.bgColor);
        template = template.replace(/_textColor_/g, theme.textColor);
        template = template.replace(/_navColor_/g, theme.navColor);
        template = template.replace(/_primLight_/g, theme.primLight);
        template = template.replace(/_primDark_/g, theme.primDark);
        template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')));
        try {
            const pug = (await import('pug')).default;
            const fn = pug.compile(template);
            const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`;
            challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
                return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>');
            });
            res.set({
                'Content-Security-Policy': CSP
            });
            res.send(fn(user));
        }
        catch (err) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        }
    };
}
