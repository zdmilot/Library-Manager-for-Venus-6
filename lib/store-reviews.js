/**
 * store-reviews.js — GitHub Discussions-based rating & review system
 * for the Library Manager Marketplace.
 *
 * Uses a GitHub App (discussion read/write only) to post and read
 * per-library discussion threads in the Library-Manager-Packages repo.
 *
 * Rating data is stored as structured JSON in discussion comments.
 * Each library gets one discussion (created on first review).
 * Each comment is a review with a star rating + text.
 */

'use strict';

var crypto = require('crypto');
var https  = require('https');

// ── GitHub App Configuration ─────────────────────────────────────────
var _GH_APP_ID        = '3101051';
var _GH_INSTALL_ID    = '';  // populated at runtime via API
var _GH_OWNER         = 'zdmilot';
var _GH_REPO          = 'Library-Manager-Packages';
var _GH_DISCUSSION_CATEGORY = 'General'; // discussion category in the repo

// ── Obfuscated App Private Key ───────────────────────────────────────
// The key is XOR-encrypted, split into shuffled chunks.
// This is NOT security — it is deterrence against casual inspection.
var _eC = ["/1Dc5AuZNB1CoPD6PuqSDVKUiJiIylThVO9J9Kr4qM0puVTzOWqzvIeyQ+lRxtPL/MYfyJ7u7Onc","JUbrQ/+4G1iZVpq37IeORud1Iw2L6ZfloxsDkylsYtW6h6JQLoiBSaD+TMcdwG2oakp3TmLDS6L/","vskw8RBOVzOFdiLp754I20mYUdx8bJ2KOc4zKYcZ3bCFr1Lt6qH44b/Q9G6HwJG9eHTSFKE66yNa","zTPbVJOpQvrmObghRnorovgVbGrIKsAmgUMevnEDeDjCSHLUmhVtz2Edl1J4Lk8s+6tvIec5oM4/","N2VVJgeQLB9l6zifxOHaiHdDECtIj4mwYoPO38datrDj8jiwGI5jQNkY8gTcqgXsI6prmjaandMn","Zj23e4P1QnGX1yVBTf0RcY6FY1KDyxKZOdvKFiwnIDLatFWzKAAT0FS2tfSQBeCHhcP86svESsY4","9m+9IQjcIgYSx/gvJIHXpzbCogWzAHzbaQ==","+pbBW6GVW3Yhx4SErmg8GCToEvkS3lm4HWOP75SueKuf64XvkbrAmWNFg2D8DM4ltegSulOiLahI","IZKXdrhZou5GgGx/DBqdDAD2ZwA+teXw370xrf0WRmFjKu99lhnj+2sAEmpfEURQgL+ZqbqNMOvA","Gk6AtAoIjcxmn9QySmTuO+5ZN9MOd6b6vUJq1I1zKr3HWBE31ChuBmy7/eDkL6SYfEBxnwpkxHWy","5rWSPG+SUOWNRkJ7XLeUyn2l7/0BbAaxOBGwNWGSQ7ZXpeQ+ZcyAtQDKlzYP95zwIL3pJJyb/yfI","0LJhXBRlPxeFyXRDIpTss3JIEbvPFHVBThodBLyNbQy7fn4+mIGBWGWAXHGJIv3ygW3T0haXBUaE","yzdsC219g0eiovpo6IxCzHLcyVJtQVHwahrrYiqLY0agD1Uowmu/bmLhe/pWO+NLKZKK9k+D+zF/","tfhPCl8mAkA9Q4qfP/dNXEUQET8UObpy9VkbKD0UIJXFuGX6YU+L4VONmQqL0Zn+sfcILyuqwANd","eV8QmyKNTJ6DSK5wNpX5d5ROozZT5ecfDA3/FVzzWEjTRWwzdb/QVMaggZcUv+yBrKIQe3ID0vxX","hQImXqDHSRX+38/rW2OplW5qv6jW2MnoKMAc9v0LAX8HXC4giF1hcv8xD3MYp8KVvcBSx1SSXcph","0OOZ2UMsIjl6NX4+nMDl3OvOvmc9fUwmdKkBsNXy+I6CUcRPqiO/j4WpQRYFFFRLT7EZMzFqiypF","lEM6smpjjX/6gjXBTEli5vvMwPDqMNEqF8FN0TETVJdS4xMDzXUFa6QtjLXvjjP9ncPGY82j42Pz","HTToXr7VI1YCpHJdiii9utJmMhrut5gkDRncTC4WBZg4SsuvjrEwH8Zgs2mUNBK3fjhDlfByrJXL","y8ghqCXJcRZoqQ+53ZLqL7EK1/ROV6GhmTbTi61g23bbUnT4aWNIY9XIzJe0AX6J7SOr0GssYBj3","F+u6GWYBlrGU8I3vmta47kAANQBtzMdEDwIqmgYpcJ6/CmzL3PZfI2dnyYDpilVYs7fYLorCMrgW","SRxJvMUculMyd/49fkJH+an/Zu5hsJ7c5c/zLeqkyeHAz5SH6AaeB0p/+n1PR7n0j1wJSdeLXVuX","vaTcWXGhy67CvYUyvd+MZ2WEiMSHI/VGRCYOBPS+t4dwri4oWpqF+sSzr6WGzSP+VZmmg+zKecNh","oap4HU7rkuwsBfiT/1hA2mUkcPpVRPLUTnhyLOifYlL9aAsa7Nx6ykvsoiPgxC7yOTTJNfSCSClT","eeIoCDFolAe6Q4tnao4dIgH8+n4DjLuOSa4T9qSh/pp05jKJetimtEqG10B5C5D5hIMz+D7vduNG","Trtltb+KcFu1DTRX/f1WaQKMBKIBUsAPTtcxV8gDSOelDr9UEOPxqJuVEMKcVU76w6B/eWjPmKX4","xZ9jHHnOiikx3jMcsAPVMRqfYTRMWIe7sihUk+4BIOfsyRmDMul+nCOfv8QiuBw1KLXwlToIb83Q","rJqmGoz9Sx5h4jvYfG48txwvixfe55TK2HldYXsTf4b/7eZa1PHW1L3iFnwc6fXyNtn+51nlPY7N","B8vf9o5in1OQlyoanNEpPpfN+xUqVkMk6comZmCeFOtbA3f04BSKNTnVXd3q/1FTPnd3G5A8uIdy","xv5stPR26l05tXFPkE75vvbSsJnV9SGgeCqr0bqgCaxeMwUK1kMSAVeDAb5AUopctfSikZ1w0S2W"];
var _kC = ["0n3xySbbcVoL7tCobauyXQDd3tncj3SqEbZk2YfVhcdk8B22SSv6/sbzCKoQl5aKzZRuu8eW3tm7","cS2SFovRVm32D+L72vHMJagnUknNqsG10ytX8nMIJoX445sefMnDeti1Orco+WfBCxgEJCf0PenL","/6Vdkl0Fb3vgThGwquxamBzgEOQ/GPTtb7h6HO5apMry7SuFwdnNptSHsQfDp9m3TAa0W+BMhXIv","phjoNdToMsjfb4lgBEphk5NTJFvCT6JFyjNR50RaHxeQLB+H3VQKuyJXpBseRTZhq/o5QtV804Zs","RCthTHfYSXUmul3yga2WxlgsZlwchcLaL+78nPQ788CVkG+GdvwVLJR1qmmv5TKIEOU8qWb9z5ZD","MnPOM/SCERntoG01AI9SXsSzDguo+ivNUpOnc1pQKn2W136KEE5Sphvl5KCib5WxzrqXj4KsKfYI","2yrzZSiOcUcyl6pmcsCD4haJ51yeLVH2RA==","u9SANOjXGjJXo/3TnRFFKm2/R75jh1PSTzLrn6znCtjOj8+ApO6owAACximeTYJw945R+SDVS5wQ","dfihFPtuqIwh7gQKdCu2aGHZFWZ78NyCuPsCnaRhDy8WQ4EZ4ki6zSV5WRwbSGsl4YbL0cm6fqix","WSPBx0N81IAP8OcLG26kWL0fXPxrR8DN8jI94OgAU/WQaXddgW0XalTWk4+mH+vVTi0523wIjgSL","n93VbCnKIKDpc3IsEdL7mB6dg8pQD3/hD1XyDQrmCPAP44B4FbWKzTCQ9k9CstqKdPvZU/7JjUCC","kdAOPU4QdVz/oD1zVPXDxQs6Yvb6IgIJFk98YI7vI2neCCxxyra3KFLqbCa6Scy50yC5hRzxS37D","nF9HaVtWziTAw8IxsrsGtUW1rzs+KT64DXaDUn7aUSjxehhBrGHIQVerEawacrQ7TertvSHaw1ks","zKgdRB5lcRR2G/DXTaMHPypxaU1RbvkEwRc0URJyRfyv/D+LayzErWrLyEHJtsi9y8NReGD4rEsz","EWZq4UjkJeb5GOYdVdmKNN4/6Wc4kIIrWmLHdh+UAQ2SNSFnJdbiH6nP884h78PW7shiMyYJkc8B","609eMOb+D0bVroeMag7e2F8s5/m7sZqBRYRGl49ZMDdzKGwXxAoSeKZENktWwqTF6qIhhgzIEv8U","+6D6vhtORWobAylN0/ST6IigzFd+GhVjNZxL9OP4n+bBY50hmFLU+PObBlRTdiceINZyZWYFun10","2itiyhk55SiJ6H60dXtSt5S5jYPbRrpMVoUeiwB4FqYhiHpUg0E3IctHtYy563+s7Y6HD5T2pGnA","SX+bK9+8DDhL1kUo60H29oYlBnSN/u0dOF2QdVZ8bKtSe5jWw4BCda8lyQ/sRHPiN3l+qPpfgbjm","oLJ4n1SAJScRn1X/l8KJQfpo4t8rDvmYrleJ6cIh6weRBDDNXFMmOeOvlK7yMhba3W2A4x8YES6l","VqPgLWx5x+n9ncmMw+eX3SQzZUMOtpEIdVQe315rRuTebAnz6q9odRAsnuiduxhv6+eBGv7pVPYi","eXYN049IgwJdFbp8LDUBidqtUtcX59uplIOUToH9kIOv4MXgrlb5RhwyvhgJNc+51woxKODkEj/b","3Ma4ajDo/8ey/O1ajbXJJgvUxqD3eZYoNmA+Yt+N3P4nmn1Odev/w7Pc1pfIxxWGENTuypS4QPcl","7IUiRR+a06FYVo/kvBE17T9AIpETDbqAFxRLdNipEAbPXlNL2bQsgn+WlEXqrFe2T0WBUZLzJBAE","F6EceUcn3ijpFdEgCPckVmfJwgtB4ei/eep4psvYv9EGs1zdCK7U5AjSgAQWQ+Ga5vJnlE26PdAF","JcFSzN7hHzCaNUAik8URP1DOQMk5H4NVPqIGIr53LNHHeNEOX5Cm4v/kKYitEAOQ8MoqGAH+kuzP","9K4lfwy52X5wtFR9ukntWHvlVnwuIfSK4mtj9INVbIu4pVPocY4n3Uv+yK904mZSQuyc/X9FWZqS","/v6TWNm0c24bk06QFTZZ3mRlsl2bleOelT8qEXE8Kb7Qvqc/l9qRvvjJXSxSqLifBLWapBecR8Xm","Ub++gM1o1CXh1Hl095JOZ9KMzGQcDBoL0JIJH1PcV98BZUagqXr+ZQyvOJDfzSs4CiAVV9Jq4PdA","jokY7K1OiGlT9iV532HzjLGT+fyUhBTJC1LZlNLJceEPZnVurnBrODz7VY8kOMg6+7+Vp+o5lWzH"];
var _rM = [0,15,2,17,21,8,29,7,5,10,1,25,24,28,9,4,16,12,22,14,19,20,26,3,27,13,23,11,18,6];

/** Reassemble and decrypt the private key at runtime. */
function _dk() {
    // Unshuffle chunks using the reorder map
    var eJ = '', kJ = '';
    for (var i = 0; i < _rM.length; i++) {
        eJ += _eC[_rM[i]];
        kJ += _kC[_rM[i]];
    }
    var eB = Buffer.from(eJ, 'base64');
    var kB = Buffer.from(kJ, 'base64');
    var r = Buffer.alloc(eB.length);
    for (var j = 0; j < eB.length; j++) r[j] = eB[j] ^ kB[j];
    return r.toString('utf8');
}

// ── JWT Generation ───────────────────────────────────────────────────
/** Create a base64url-encoded string. */
function _b64url(buf) {
    return buf.toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Generate a GitHub App JWT (valid for up to 10 minutes).
 * @returns {string} JWT token
 */
function _generateJWT() {
    var now = Math.floor(Date.now() / 1000);
    var header  = { alg: 'RS256', typ: 'JWT' };
    var payload = {
        iat: now - 60,       // issued 60s ago to account for clock drift
        exp: now + (9 * 60), // expires in 9 minutes
        iss: _GH_APP_ID
    };

    var segments = _b64url(Buffer.from(JSON.stringify(header))) + '.' +
                   _b64url(Buffer.from(JSON.stringify(payload)));

    var pem = _dk();
    var sign = crypto.createSign('RSA-SHA256');
    sign.update(segments);
    var signature = sign.sign(pem);

    return segments + '.' + _b64url(signature);
}

// ── HTTPS helpers ────────────────────────────────────────────────────
/**
 * Make an HTTPS request and return parsed JSON.
 * @param {object} opts - request options
 * @param {string|null} body - request body (JSON string)
 * @param {function} cb - callback(err, data)
 */
function _ghRequest(opts, body, cb) {
    opts.headers = opts.headers || {};
    opts.headers['User-Agent'] = 'Library-Manager-Store';
    opts.headers['Accept'] = 'application/vnd.github+json';
    if (body) {
        opts.headers['Content-Type'] = 'application/json';
        opts.headers['Content-Length'] = Buffer.byteLength(body);
    }

    var req = https.request(opts, function (res) {
        var chunks = [];
        res.on('data', function (c) { chunks.push(c); });
        res.on('end', function () {
            var raw = Buffer.concat(chunks).toString('utf8');
            try {
                var parsed = JSON.parse(raw);
                if (res.statusCode >= 400) {
                    var errMsg = parsed.message || ('HTTP ' + res.statusCode);
                    return cb(new Error(errMsg));
                }
                cb(null, parsed);
            } catch (e) {
                cb(new Error('JSON parse error: ' + raw.substring(0, 200)));
            }
        });
    });
    req.on('error', function (e) { cb(e); });
    req.setTimeout(30000, function () { req.destroy(); cb(new Error('Timeout')); });
    if (body) req.write(body);
    req.end();
}

// ── Installation Access Token ────────────────────────────────────────
var _cachedToken = null;
var _cachedTokenExpiry = 0;

/**
 * Get a valid installation access token (cached until near expiry).
 * First finds the installation ID for our repo, then creates a token.
 */
function _getInstallationToken(cb) {
    var now = Date.now();
    if (_cachedToken && now < _cachedTokenExpiry) {
        return cb(null, _cachedToken);
    }

    var jwt = _generateJWT();

    // Step 1: Find the installation for our repo
    _ghRequest({
        hostname: 'api.github.com',
        path: '/repos/' + _GH_OWNER + '/' + _GH_REPO + '/installation',
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + jwt }
    }, null, function (err, data) {
        if (err) return cb(err);
        if (!data || !data.id) return cb(new Error('No installation found'));

        _GH_INSTALL_ID = String(data.id);

        // Step 2: Create an installation access token
        _ghRequest({
            hostname: 'api.github.com',
            path: '/app/installations/' + _GH_INSTALL_ID + '/access_tokens',
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + jwt }
        }, '{}', function (err2, tokenData) {
            if (err2) return cb(err2);
            _cachedToken = tokenData.token;
            // Token expires in 1 hour, cache for 50 min
            _cachedTokenExpiry = now + (50 * 60 * 1000);
            cb(null, _cachedToken);
        });
    });
}

// ── GraphQL helpers ──────────────────────────────────────────────────
/**
 * Execute a GitHub GraphQL query with the installation token.
 */
function _graphql(query, variables, cb) {
    _getInstallationToken(function (err, token) {
        if (err) return cb(err);

        var body = JSON.stringify({ query: query, variables: variables || {} });
        _ghRequest({
            hostname: 'api.github.com',
            path: '/graphql',
            method: 'POST',
            headers: { 'Authorization': 'token ' + token }
        }, body, function (err2, data) {
            if (err2) return cb(err2);
            if (data.errors && data.errors.length > 0) {
                return cb(new Error(data.errors[0].message));
            }
            cb(null, data.data);
        });
    });
}

// ── Discussion Category ID ───────────────────────────────────────────
var _cachedCategoryId = null;

function _getDiscussionCategoryId(cb) {
    if (_cachedCategoryId) return cb(null, _cachedCategoryId);

    var q = 'query($owner:String!,$repo:String!){repository(owner:$owner,name:$repo){discussionCategories(first:25){nodes{id,name}}}}';
    _graphql(q, { owner: _GH_OWNER, repo: _GH_REPO }, function (err, data) {
        if (err) return cb(err);
        var cats = data.repository.discussionCategories.nodes;
        for (var i = 0; i < cats.length; i++) {
            if (cats[i].name === _GH_DISCUSSION_CATEGORY) {
                _cachedCategoryId = cats[i].id;
                return cb(null, _cachedCategoryId);
            }
        }
        cb(new Error('Discussion category "' + _GH_DISCUSSION_CATEGORY + '" not found. Please create it in the repository.'));
    });
}

// ── Repository ID ────────────────────────────────────────────────────
var _cachedRepoId = null;

function _getRepoId(cb) {
    if (_cachedRepoId) return cb(null, _cachedRepoId);

    var q = 'query($owner:String!,$repo:String!){repository(owner:$owner,name:$repo){id}}';
    _graphql(q, { owner: _GH_OWNER, repo: _GH_REPO }, function (err, data) {
        if (err) return cb(err);
        _cachedRepoId = data.repository.id;
        cb(null, _cachedRepoId);
    });
}

// ── Review Data Format ───────────────────────────────────────────────
// Each review comment has a structured block at the end:
//   <!-- REVIEW_DATA:{"rating":5,"username":"JohnDoe","timestamp":"..."} -->
// This lets us parse ratings from comment bodies reliably.

var REVIEW_DATA_RE = /<!-- REVIEW_DATA:(.*?) -->/;
var RATING_HEADER_RE = /<!-- RATING_SUMMARY:(.*?) -->/;

function _parseReviewData(body) {
    var m = REVIEW_DATA_RE.exec(body);
    if (!m) return null;
    try { return JSON.parse(m[1]); } catch (_) { return null; }
}

function _buildReviewBody(username, rating, comment, systemInfo) {
    var stars = '';
    for (var i = 0; i < 5; i++) {
        stars += (i < rating) ? ':star:' : ':black_small_square:';
    }
    var text = '### ' + stars + ' (' + rating + '/5)\n\n';
    if (comment) text += comment + '\n\n';
    text += '---\n';
    text += '_Reviewed by **' + username + '**_\n\n';
    var payload = {
        rating: rating,
        username: username,
        timestamp: new Date().toISOString()
    };
    if (systemInfo) {
        if (systemInfo.windowsVersion) payload.windows_version = systemInfo.windowsVersion;
        if (systemInfo.venusVersion)   payload.venus_version   = systemInfo.venusVersion;
        if (systemInfo.libraryVersion) payload.library_version  = systemInfo.libraryVersion;
        if (systemInfo.appVersion)     payload.app_version      = systemInfo.appVersion;
    }
    text += '<!-- REVIEW_DATA:' + JSON.stringify(payload) + ' -->';
    return text;
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Find the discussion for a library by title.
 * Returns {id, number, title, body, url} or null if not found.
 */
function findDiscussion(libraryName, cb) {
    // Search discussions by title
    var q = 'query($owner:String!,$repo:String!,$query:String!){' +
        'repository(owner:$owner,name:$repo){' +
        'discussions(first:5,filterBy:{categories:[]},orderBy:{field:CREATED_AT,direction:DESC}){nodes{id,number,title,body,url}}}}';

    // Use the search API for more precise matching
    var searchQ = 'query($q:String!){search(query:$q,type:DISCUSSION,first:5){nodes{...on Discussion{id,number,title,body,url,repository{owner{login},name}}}}}';
    var searchStr = '"[Library Review] ' + libraryName + '" repo:' + _GH_OWNER + '/' + _GH_REPO;

    _graphql(searchQ, { q: searchStr }, function (err, data) {
        if (err) return cb(err);
        var nodes = data.search.nodes || [];
        var exactTitle = '[Library Review] ' + libraryName;
        for (var i = 0; i < nodes.length; i++) {
            if (nodes[i].title === exactTitle) return cb(null, nodes[i]);
        }
        cb(null, null);
    });
}

/**
 * Create a new discussion for a library.
 */
function createDiscussion(libraryName, cb) {
    _getRepoId(function (err, repoId) {
        if (err) return cb(err);
        _getDiscussionCategoryId(function (err2, catId) {
            if (err2) return cb(err2);

            var title = '[Library Review] ' + libraryName;
            var body = '# ' + libraryName + ' — Ratings & Reviews\n\n' +
                'This discussion collects community ratings and reviews for the **' + libraryName + '** library.\n\n' +
                'Post a comment below to leave your review!\n\n' +
                '<!-- RATING_SUMMARY:' + JSON.stringify({ total: 0, sum: 0, count: 0 }) + ' -->';

            var mutation = 'mutation($input:CreateDiscussionInput!){createDiscussion(input:$input){discussion{id,number,title,body,url}}}';
            _graphql(mutation, {
                input: {
                    repositoryId: repoId,
                    categoryId: catId,
                    title: title,
                    body: body
                }
            }, function (err3, data) {
                if (err3) return cb(err3);
                cb(null, data.createDiscussion.discussion);
            });
        });
    });
}

/**
 * Get or create the discussion for a library.
 */
function getOrCreateDiscussion(libraryName, cb) {
    findDiscussion(libraryName, function (err, disc) {
        if (err) return cb(err);
        if (disc) return cb(null, disc);
        createDiscussion(libraryName, cb);
    });
}

/**
 * Get all reviews (comments) for a library's discussion.
 * Returns { reviews: [{username, rating, comment, createdAt, id}], averageRating, totalReviews }
 */
function getReviews(libraryName, cb) {
    findDiscussion(libraryName, function (err, disc) {
        if (err) return cb(err);
        if (!disc) return cb(null, { reviews: [], averageRating: 0, totalReviews: 0 });

        // Fetch comments on the discussion
        var q = 'query($owner:String!,$repo:String!,$num:Int!){' +
            'repository(owner:$owner,name:$repo){' +
            'discussion(number:$num){' +
            'comments(first:100,orderBy:{field:CREATED_AT,direction:DESC}){' +
            'nodes{id,body,createdAt,author{login}}' +
            '}}}}';

        _graphql(q, { owner: _GH_OWNER, repo: _GH_REPO, num: disc.number }, function (err2, data) {
            if (err2) return cb(err2);
            var commentNodes = data.repository.discussion.comments.nodes || [];
            var reviews = [];
            var sum = 0;
            for (var i = 0; i < commentNodes.length; i++) {
                var rd = _parseReviewData(commentNodes[i].body);
                if (rd) {
                    // Strip the metadata from display body
                    var displayBody = commentNodes[i].body
                        .replace(REVIEW_DATA_RE, '')
                        .replace(/---\s*\n_Reviewed by \*\*.*?\*\*_\s*$/s, '')
                        .replace(/^### .*?\n\n/, '')
                        .trim();
                    reviews.push({
                        id: commentNodes[i].id,
                        username: rd.username || (commentNodes[i].author ? commentNodes[i].author.login : 'Anonymous'),
                        rating: rd.rating,
                        comment: displayBody,
                        createdAt: commentNodes[i].createdAt,
                        timestamp: rd.timestamp
                    });
                    sum += rd.rating;
                }
            }
            cb(null, {
                reviews: reviews,
                averageRating: reviews.length > 0 ? Math.round((sum / reviews.length) * 10) / 10 : 0,
                totalReviews: reviews.length,
                discussionUrl: disc.url
            });
        });
    });
}

/**
 * Submit a review for a library.
 * @param {string} libraryName
 * @param {string} username - Windows username of the reviewer
 * @param {number} rating - 1 to 5
 * @param {string} comment - Review text
 * @param {object} [systemInfo] - Optional system details {windowsVersion, venusVersion, libraryVersion, appVersion}
 * @param {function} cb - callback(err, review)
 */
function submitReview(libraryName, username, rating, comment, systemInfo, cb) {
    if (typeof systemInfo === 'function') { cb = systemInfo; systemInfo = null; }
    if (rating < 1 || rating > 5) return cb(new Error('Rating must be 1-5'));

    getOrCreateDiscussion(libraryName, function (err, disc) {
        if (err) return cb(err);

        var body = _buildReviewBody(username, rating, comment, systemInfo);

        var mutation = 'mutation($input:AddDiscussionCommentInput!){addDiscussionComment(input:$input){comment{id,body,createdAt}}}';
        _graphql(mutation, {
            input: {
                discussionId: disc.id,
                body: body
            }
        }, function (err2, data) {
            if (err2) return cb(err2);
            cb(null, {
                id: data.addDiscussionComment.comment.id,
                username: username,
                rating: rating,
                comment: comment,
                createdAt: data.addDiscussionComment.comment.createdAt
            });
        });
    });
}

/**
 * Batch-fetch average ratings for multiple libraries at once.
 * Uses GitHub search to find all review discussions, avoids N+1 queries.
 * Returns a map: { libraryName: { averageRating, totalReviews } }
 */
function batchGetRatings(libraryNames, cb) {
    if (!libraryNames || libraryNames.length === 0) return cb(null, {});

    // Search for all review discussions in the repo
    var searchQ = 'query($q:String!){search(query:$q,type:DISCUSSION,first:100){nodes{...on Discussion{title,comments(first:100){nodes{body}}}}}}';
    var q = '"[Library Review]" repo:' + _GH_OWNER + '/' + _GH_REPO;

    _graphql(searchQ, { q: q }, function (err, data) {
        if (err) return cb(err);

        var results = {};
        var nodes = data.search.nodes || [];

        // Initialize all requested libraries
        for (var n = 0; n < libraryNames.length; n++) {
            results[libraryNames[n]] = { averageRating: 0, totalReviews: 0 };
        }

        for (var i = 0; i < nodes.length; i++) {
            var title = nodes[i].title || '';
            var match = title.match(/^\[Library Review\] (.+)$/);
            if (!match) continue;
            var libName = match[1];
            if (!results.hasOwnProperty(libName)) continue;

            var comments = nodes[i].comments.nodes || [];
            var sum = 0, count = 0;
            for (var c = 0; c < comments.length; c++) {
                var rd = _parseReviewData(comments[c].body);
                if (rd && rd.rating >= 1 && rd.rating <= 5) {
                    sum += rd.rating;
                    count++;
                }
            }
            results[libName] = {
                averageRating: count > 0 ? Math.round((sum / count) * 10) / 10 : 0,
                totalReviews: count
            };
        }

        cb(null, results);
    });
}

// ── Exports ──────────────────────────────────────────────────────────
module.exports = {
    getReviews: getReviews,
    submitReview: submitReview,
    findDiscussion: findDiscussion,
    getOrCreateDiscussion: getOrCreateDiscussion,
    batchGetRatings: batchGetRatings
};
