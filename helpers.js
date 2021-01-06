const node_fetch = require("node-fetch");
const crypto = require("crypto");
const dateformat = require('./dateformat');
const FS = require("fs");
const Path = require("path");
const Portscanner = require("portscanner");
const XXHash = require('xxhash');

const PORT_RANGE = [62900, 63900];
const deafultXXSalt = [63, 109, 68, 53, 45, 75, 111, 22];
const ALPHA_NUM_ARR = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

class Performance {
    static now() {
        const hrTime = process.hrtime();
        return (hrTime[0] + (hrTime[1] / 1e9)) * 1000;
    }

    static diff(lastTime) {
        const hrTime = process.hrtime();
        return ((hrTime[0] + (hrTime[1] / 1e9)) * 1000) - lastTime;
    }
}

function recurseDirectory(dir, callback) {
    return new Promise((resolve, reject) => {
        try {
            var results = [];
            FS.readdir(dir, function (err, list) {
                if (err) return reject(err);
                (function next(i) {
                    var file = list[i++];
                    if (!file) {
                        resolve(results.filter(onlyUnique));
                    } else {
                        file = Path.resolve(dir, file);
                        FS.stat(file, function (err, stat) {
                            if (stat && stat.isDirectory()) {
                                if (typeof callback === "function") callback(file);
                                recurseDirectory(file).then((res) => {
                                    res.forEach((t) => {
                                        if (!results.includes(t)) results.push(t);
                                        if (typeof callback === "function") callback(t);
                                    });
                                    next(i);
                                }).catch(reject);
                            } else {
                                if (!results.includes(file)) results.push(file);
                                if (typeof callback === "function") callback(file);
                                next(i);
                            }
                        });
                    }
                })(0);
            });
        } catch (e) {
            reject(e);
        }
    });
}

function onlyUnique(value, index, self) {
    return self.indexOf(value) === index;
}

module.exports = class Helpers {
};

module.exports.performance = Performance;

/**
 * @param input
 * @param key
 * @param encoding
 * @returns {Buffer}
 */
module.exports.xxHash = (input, key = null, encoding = "hex") => {
    switch (key) {
        case "binary":
        case "hex":
        case "base64":
        case "buffer":
            encoding = key;
            key = deafultXXSalt;
            break;
        default:
            if (typeof key === "string") {
                if (key.length > 8) {
                    key = XXHash.hash64(Buffer.from(key), Buffer.from(deafultXXSalt), "buffer");
                } else if (key.length < 8) {
                    key += deafultXXSalt.slice(0, 8 - key.length).map((c) => String.fromCharCode(c)).join("");
                }
            } else {
                key = deafultXXSalt;
            }
            break;
    }
    return XXHash.hash64(Buffer.from(input), Buffer.isBuffer(key) ? key : Buffer.from(key), encoding);
};

module.exports.fetch = (url, options = {}) => {
    return new Promise((resolve, reject) => {
        node_fetch(url, options).then(async (res) => {
            const raw = await res.text().catch((e) => reject({error: e.message, url: url, status: 0}));
            if (res.status < 400) {
                try {
                    resolve(JSON.parse(raw));
                } catch (e) {
                    reject({error: e.message, url: url, status: res.status, raw: raw});
                }
            } else {
                reject({error: res.statusText, url: url, status: res.status});
            }
        }).catch((e) => reject({error: e.message, url: url, status: 0}));
    });
};

module.exports.formatDate = (format, date = new Date(), utc = false) => {
    return dateformat(date, format, utc);
};

module.exports.hmac = (input, key) => {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(input);
    return hmac.digest('hex');
};

module.exports.sha256 = (input) => {
    return crypto.createHash("sha256")
        .update(input)
        .digest("hex");
};

module.exports.md5 = (input_data) => {

    function md5cycle(x, k) {
        var a = x[0], b = x[1], c = x[2], d = x[3];

        a = ff(a, b, c, d, k[0], 7, -680876936);
        d = ff(d, a, b, c, k[1], 12, -389564586);
        c = ff(c, d, a, b, k[2], 17, 606105819);
        b = ff(b, c, d, a, k[3], 22, -1044525330);
        a = ff(a, b, c, d, k[4], 7, -176418897);
        d = ff(d, a, b, c, k[5], 12, 1200080426);
        c = ff(c, d, a, b, k[6], 17, -1473231341);
        b = ff(b, c, d, a, k[7], 22, -45705983);
        a = ff(a, b, c, d, k[8], 7, 1770035416);
        d = ff(d, a, b, c, k[9], 12, -1958414417);
        c = ff(c, d, a, b, k[10], 17, -42063);
        b = ff(b, c, d, a, k[11], 22, -1990404162);
        a = ff(a, b, c, d, k[12], 7, 1804603682);
        d = ff(d, a, b, c, k[13], 12, -40341101);
        c = ff(c, d, a, b, k[14], 17, -1502002290);
        b = ff(b, c, d, a, k[15], 22, 1236535329);

        a = gg(a, b, c, d, k[1], 5, -165796510);
        d = gg(d, a, b, c, k[6], 9, -1069501632);
        c = gg(c, d, a, b, k[11], 14, 643717713);
        b = gg(b, c, d, a, k[0], 20, -373897302);
        a = gg(a, b, c, d, k[5], 5, -701558691);
        d = gg(d, a, b, c, k[10], 9, 38016083);
        c = gg(c, d, a, b, k[15], 14, -660478335);
        b = gg(b, c, d, a, k[4], 20, -405537848);
        a = gg(a, b, c, d, k[9], 5, 568446438);
        d = gg(d, a, b, c, k[14], 9, -1019803690);
        c = gg(c, d, a, b, k[3], 14, -187363961);
        b = gg(b, c, d, a, k[8], 20, 1163531501);
        a = gg(a, b, c, d, k[13], 5, -1444681467);
        d = gg(d, a, b, c, k[2], 9, -51403784);
        c = gg(c, d, a, b, k[7], 14, 1735328473);
        b = gg(b, c, d, a, k[12], 20, -1926607734);

        a = hh(a, b, c, d, k[5], 4, -378558);
        d = hh(d, a, b, c, k[8], 11, -2022574463);
        c = hh(c, d, a, b, k[11], 16, 1839030562);
        b = hh(b, c, d, a, k[14], 23, -35309556);
        a = hh(a, b, c, d, k[1], 4, -1530992060);
        d = hh(d, a, b, c, k[4], 11, 1272893353);
        c = hh(c, d, a, b, k[7], 16, -155497632);
        b = hh(b, c, d, a, k[10], 23, -1094730640);
        a = hh(a, b, c, d, k[13], 4, 681279174);
        d = hh(d, a, b, c, k[0], 11, -358537222);
        c = hh(c, d, a, b, k[3], 16, -722521979);
        b = hh(b, c, d, a, k[6], 23, 76029189);
        a = hh(a, b, c, d, k[9], 4, -640364487);
        d = hh(d, a, b, c, k[12], 11, -421815835);
        c = hh(c, d, a, b, k[15], 16, 530742520);
        b = hh(b, c, d, a, k[2], 23, -995338651);

        a = ii(a, b, c, d, k[0], 6, -198630844);
        d = ii(d, a, b, c, k[7], 10, 1126891415);
        c = ii(c, d, a, b, k[14], 15, -1416354905);
        b = ii(b, c, d, a, k[5], 21, -57434055);
        a = ii(a, b, c, d, k[12], 6, 1700485571);
        d = ii(d, a, b, c, k[3], 10, -1894986606);
        c = ii(c, d, a, b, k[10], 15, -1051523);
        b = ii(b, c, d, a, k[1], 21, -2054922799);
        a = ii(a, b, c, d, k[8], 6, 1873313359);
        d = ii(d, a, b, c, k[15], 10, -30611744);
        c = ii(c, d, a, b, k[6], 15, -1560198380);
        b = ii(b, c, d, a, k[13], 21, 1309151649);
        a = ii(a, b, c, d, k[4], 6, -145523070);
        d = ii(d, a, b, c, k[11], 10, -1120210379);
        c = ii(c, d, a, b, k[2], 15, 718787259);
        b = ii(b, c, d, a, k[9], 21, -343485551);

        x[0] = add32(a, x[0]);
        x[1] = add32(b, x[1]);
        x[2] = add32(c, x[2]);
        x[3] = add32(d, x[3]);

    }

    function cmn(q, a, b, x, s, t) {
        a = add32(add32(a, q), add32(x, t));
        return add32((a << s) | (a >>> (32 - s)), b);
    }

    function ff(a, b, c, d, x, s, t) {
        return cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }

    function gg(a, b, c, d, x, s, t) {
        return cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }

    function hh(a, b, c, d, x, s, t) {
        return cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function ii(a, b, c, d, x, s, t) {
        return cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    function md51(s) {
        txt = '';
        var n = s.length,
            state = [1732584193, -271733879, -1732584194, 271733878], i;
        for (i = 64; i <= s.length; i += 64) {
            md5cycle(state, md5blk(s.substring(i - 64, i)));
        }
        s = s.substring(i - 64);
        var tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < s.length; i++)
            tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3);
        if (i > 55) {
            md5cycle(state, tail);
            for (i = 0; i < 16; i++) tail[i] = 0;
        }
        tail[14] = n * 8;
        md5cycle(state, tail);
        return state;
    }

    /* there needs to be support for Unicode here,
     * unless we pretend that we can redefine the MD-5
     * algorithm for multi-byte characters (perhaps
     * by adding every four 16-bit characters and
     * shortening the sum to 32 bits). Otherwise
     * I suggest performing MD-5 as if every character
     * was two bytes--e.g., 0040 0025 = @%--but then
     * how will an ordinary MD-5 sum be matched?
     * There is no way to standardize text to something
     * like UTF-8 before transformation; speed cost is
     * utterly prohibitive. The JavaScript standard
     * itself needs to look at this: it should start
     * providing access to strings as preformed UTF-8
     * 8-bit unsigned value arrays.
     */
    function md5blk(s) { /* I figured global was faster.   */
        var md5blks = [], i; /* Andy King said do it this way. */
        for (i = 0; i < 64; i += 4) {
            md5blks[i >> 2] = s.charCodeAt(i)
                + (s.charCodeAt(i + 1) << 8)
                + (s.charCodeAt(i + 2) << 16)
                + (s.charCodeAt(i + 3) << 24);
        }
        return md5blks;
    }

    var hex_chr = '0123456789abcdef'.split('');

    function rhex(n) {
        var s = '', j = 0;
        for (; j < 4; j++)
            s += hex_chr[(n >> (j * 8 + 4)) & 0x0F]
                + hex_chr[(n >> (j * 8)) & 0x0F];
        return s;
    }

    function hex(x) {
        for (var i = 0; i < x.length; i++)
            x[i] = rhex(x[i]);
        return x.join('');
    }

    function _md5(s) {
        return hex(md51(s));
    }

    /* this function is much faster,
    so if possible we use it. Some IEs
    are the only ones I know of that
    need the idiotic second function,
    generated by an if clause.  */

    function add32(a, b) {
        return (a + b) & 0xFFFFFFFF;
    }

    return _md5(input_data.toString());
};

module.exports.rand = (min, max) => {
    return Math.random() * (max - min) + min;
};

module.exports.hasProp = (obj, key) => {
    //console.log(key, JSON.stringify(obj));
    if (typeof obj !== "undefined" && obj !== null) {
        return Object.prototype.hasOwnProperty.call(obj, key);
    }
    return false;
};

module.exports.isDefined = (obj) => {
    return (typeof obj !== "undefined" && obj !== null);
};

module.exports.hasPropDefined = (obj, key) => {
    if (typeof obj !== "undefined" && obj !== null) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
            if (obj[key] != null && typeof obj[key] !== "undefined" && obj[key] !== "") {
                return true;
            }
        }
    }
    return false;
};

module.exports.getChunks = (array, chunk_size) => {
    return Array(Math.ceil(array.length / chunk_size)).fill().map((_, index) => index * chunk_size).map(begin => array.slice(begin, begin + chunk_size));
};

module.exports.recurseDirectory = recurseDirectory;

module.exports.atob = (a) => {
    try {
        return Buffer.from(a, 'base64').toString('binary');
    } catch (e) {
        return "";
    }
};

module.exports.btoa = (b) => {
    if (Buffer.isBuffer(b)) {
        return b.toString('base64');
    } else {
        return Buffer.from(b).toString('base64');
    }
};

module.exports.parseCookies = (cookies, key = null) => {
    let decodedCookie = decodeURIComponent(cookies);
    let ca = decodedCookie.split(';');
    let output = {};
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i].trim();
        let ci = c.indexOf("=");
        let name = c.substr(0, ci);
        let value = c.substr(ci + 1);
        if (name === key) {
            try {
                return JSON.parse(value);
            } catch (e) {
                return value;
            }
        } else {
            try {
                output[name] = JSON.parse(value);
            } catch (e) {
                output[name] = value;
            }
        }
    }
    return (Object.keys(output).length > 0) ? output : null;
};

module.exports.createQuery = (arr) => {
    if (typeof arr === "string") {
        return [arr];
    } else if (typeof arr === "object") {
        let query = [];
        Object.keys(arr).map((key) => {
            if (Array.isArray(arr[key])) {
                arr[key].forEach((item) => {
                    query.push(`${key}=${item}`);
                });
            } else {
                query.push(`${key}=${arr[key]}`);
            }
        });
        return query;
    }
    return [arr];
};

module.exports.joinUrl = (...paths) => {
    return paths.filter((path) => path.length > 0).map((path, idx) => idx < paths.length ? path.replace(/[\/]+$|^[\/]+/gmi, "") : path).join("/");
};

module.exports.findPathOf = (fileName) => {
    return new Promise((resolve, reject) => {
        recurseDirectory(process.mainModule.path, (file) => {
            if (file.endsWith(fileName)) {
                resolve(file);
            }
        }).then(() => {
            reject({error: "file not found"});
        }).catch(reject);
    });
};

module.exports.checkPort = (port, port_range = null) => {
    return new Promise(async (resolve, reject) => {
        try {
            if (!Array.isArray(port_range)) {
                port_range = [...PORT_RANGE];
            }
            const portStatus = await Portscanner.checkPortStatus(port);
            if (portStatus !== "closed") {
                const oldPort = port;
                port = await Portscanner.findAPortNotInUse(port_range[0], port_range[port_range.length - 1]);
                console.log(`Port '${oldPort}' already in use, switching to Port '${port}'`);
            }
            resolve(port);
        } catch (err) {
            console.error(err);
            resolve(0);
        }
    });
};

module.exports.resolvePath = (...pathSegments) => {
    // if (pathSegments.length > 0 && Path.isAbsolute(pathSegments[0])) {
    //     return Path.join(pathSegments[0], ...pathSegments.slice(1));
    // }
    console.log(process.mainModule.path);
    let mainModulePathName = process.mainModule.path;/*((process.argv.length > 1 && FS.existsSync(process.argv[1])) ?
        (process.argv[1].endsWith(".js") ? Path.dirname(process.argv[1]) : process.argv[1])*/
    // if (!Path.isAbsolute(mainModulePathName)) mainModulePathName = Path.resolve(mainModulePathName);
    // pathSegments = pathSegments.filter((segment) => {
    //     if (Path.isAbsolute(segment)) {
    //         mainModulePathName = segment;
    //         return false;
    //     }
    //     return true;
    // });
    // console.log([mainModulePathName, ...pathSegments]);
    return Path.join(mainModulePathName, ...pathSegments);
};

module.exports.randomString = (length = 32) => {
    const characters = [...ALPHA_NUM_ARR].sort(() => (Math.random() - 0.5));
    let rs = '';
    for (let i = 0; i < length; i++) {
        rs += characters[Math.floor(Math.random() * (characters.length - 1))];
    }
    return rs;
};

module.exports.toHexString = (byteArray) => {
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
};

module.exports.parseQuery = (cookies) => {
    if (cookies.indexOf("?") < 0) {
        return {};
    }
    const trimRegex = /^[/?]+/gmi;
    let decodedCookie = decodeURIComponent(cookies).replace(trimRegex, () => "");

    let ca = decodedCookie.split('&');
    let output = {};
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i].trim();
        let ci = c.indexOf("=");
        let name = c.substr(0, ci);
        let value = c.substr(ci + 1);
        try {
            output[name] = JSON.parse(value);
        } catch (e) {
            output[name] = value;
        }
    }
    return output;
};

module.exports.ALPHA_NUM_ARR = [...ALPHA_NUM_ARR];

module.exports.HTTP_STATUS_CODES = {
    '200': 'OK',
    '201': 'Created',
    '202': 'Accepted',
    '203': 'Non-Authoritative Information',
    '204': 'No Content',
    '205': 'Reset Content',
    '206': 'Partial Content',
    '300': 'Multiple Choices',
    '301': 'Moved Permanently',
    '302': 'Found',
    '303': 'See Other',
    '304': 'Not Modified',
    '305': 'Use Proxy',
    '307': 'Temporary Redirect',
    '400': 'Bad Request',
    '401': 'Unauthorized',
    '402': 'Payment Required',
    '403': 'Forbidden',
    '404': 'Not Found',
    '405': 'Method Not Allowed',
    '406': 'Not Acceptable',
    '407': 'Proxy Authentication Required',
    '408': 'Request Timeout',
    '409': 'Conflict',
    '410': 'Gone',
    '411': 'Length Required',
    '412': 'Precondition Failed',
    '413': 'Request Entity Too Large',
    '414': 'Request-URI Too Long',
    '415': 'Unsupported Media Type',
    '416': 'Requested Range Not Satisfiable',
    '417': 'Expectation Failed',
    '500': 'Internal Server Error',
    '501': 'Not Implemented',
    '502': 'Bad Gateway',
    '503': 'Service Unavailable',
    '504': 'Gateway Timeout',
    '505': 'HTTP Version Not Supported'
};
