const express = require('express')
const bodyParser = require('body-parser')
const mysql = require('mysql')
const cryptoJs = require("crypto-js")
const { v4: uuidv4 } = require('uuid')
const jwt = require('jsonwebtoken')

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const app = express()
const port = process.env.PORT || 5000

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

function log(str) {
    console.log(str);
}

function checkPassword(plain, encrypt) {

    const hashedPassword = cryptoJs.AES.decrypt(
        encrypt,
        process.env.SALT
    );

    const originalPassword = hashedPassword.toString(cryptoJs.enc.Utf8);

    if (plain == originalPassword) {
        return true;
    } else {
        return false;
    }
}

function doEncrypt(s) {
    return cryptoJs.AES.encrypt(
        s,
        process.env.SALT
    ).toString();
}

function unixTimestamp() {
    return Math.floor(
        Date.now() / 1000
    )
}

// MySQL

const pool = mysql.createPool({
    connectionLimit: 10,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(401)
        req.user = user
        next()
    })

}

function insertUserInfo(id, firstName, lastName) {
    pool.getConnection((err, connection) => {
        if (err) throw err
        connection.query("INSERT INTO `auth_user_info`(`id`,`first_name`,`last_name`) VALUES(?,?,?)", [id, firstName, lastName], (err) => {
            connection.release;
        })
    })
}

async function getIpId(ip) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) throw err
            connection.query("SELECT `id` FROM `auth_ip` WHERE `ip` = ?", [ip], (err, rows) => {
                if (!err) {
                    resolve(rows[0]);
                } else {
                    reject(err);
                }
                connection.release;
            })
        })
    })
}

async function getServiceId(service) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) throw err
            connection.query("SELECT `id` FROM `auth_service` WHERE `uuid` = ?", [service], (err, rows) => {
                if (!err) {
                    resolve(rows[0]);
                } else {
                    reject(err);
                }
                connection.release;
            })
        })
    })
}

function insertHistory(uuid, uid, sid, ip) {
    pool.getConnection((err, connection) => {
        if (err) throw err

            (async () => {
                myip = 0;
                mysid = 0;
                const ipaddr = await getIpId(ip);
                const service = await getServiceId(sid);

                ipaddr.then((i) => {
                    if (i != null) {
                        myip = i.id;
                    }
                })

                service.then((i) => {
                    if (i != null) {
                        mysid = i.id;
                    }
                })

                connection.query("INSERT INTO `auth_history`(`token`,`uid`,`sid`,`ip`) VALUES(?,?,?,?)", [uuid, uid, mysid, myip], (err) => {
                    connection.release;
                    resolve("true");
                })
            })()
    })
}

function insertIp(ip) {
    pool.getConnection((err, connection) => {
        if (err) throw err
        connection.query("INSERT INTO `auth_ip`(`ip`) VALUES(?)", [ip], (err) => {
            connection.release;
        })
    })
}

function checkApi(uid, api) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) throw err
            connection.query("SELECT `is_active` FROM `auth_api` WHERE `uid` = ? AND `key` = ?", [uid, api], (err, rows) => {
                if (!err) {
                    resolve(rows[0]);
                } else {
                    reject(err);
                }
                connection.release;
            })
        })
    })
}

function checkService(sid, api) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) throw err
            connection.query("SELECT `is_active` FROM `auth_api` WHERE `uid` = (SELECT `uid` FROM `auth_service` WHERE `uuid` LIKE ?) AND `key` = ?", [sid, api], (err, rows) => {
                if (!err) {
                    resolve(rows[0]);
                } else {
                    reject(err);
                }
                connection.release;
            })
        })
    })
}

function checkAccess(email, sid) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) throw err
            connection.query("SELECT `has_access` FROM `auth_access` WHERE `uid` = (SELECT `id` from `auth_user` WHERE `email` = ?) AND `sid` = (SELECT `id` from `auth_service` WHERE `uuid` = ?)", [email, sid], (err, rows) => {
                if (!err) {
                    resolve(rows[0]);
                } else {
                    reject(err);
                }
                connection.release;
            })
        })
    })
}

function checkLoginPassword(email) {
    return new Promise((resolve, reject) => {
        pool.getConnection((err, connection) => {
            if (err) throw err
            connection.query("SELECT * from `auth_user` WHERE `email` = ?", [email], (err, rows) => {
                connection.release;
                if (!err) {
                    resolve(rows[0]);
                } else {
                    reject("Failed to login")
                }
            })
        })
    })
}

function insertUserPassword(uid, password) {
    pool.getConnection((err, connection) => {
        if (err) throw err
        connection.query("INSERT INTO `auth_password`(`uid`,`password`) VALUES(?,?)", [uid, password], (err) => {
            connection.release;
        })
    })
}

app.post('/api/v1/register', (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err
        console.log(`Connected as id ${connection.threadId}`)
        const { email, password } = req.body;
        const uuid = uuidv4();
        const pass = doEncrypt(password);

        connection.query("INSERT INTO `auth_user`(`uuid`,`email`,`password`) VALUES (?, ?, ?);", [uuid, email, pass], (err) => {
            connection.release;
            if (!err) {

                pool.getConnection((err, connection) => {
                    if (err) throw err
                    connection.query("SELECT `id` from `auth_user` WHERE `uuid` LIKE ? LIMIT 1", [uuid], (err, rows) => {
                        connection.release;
                        if (!err) {
                            insertUserInfo(rows[0].id);
                            insertUserPassword(rows[0].id, pass);
                        }
                    })
                })

                res.send({
                    "code": 200,
                    "requestId": uuidv4(),
                    "time": unixTimestamp(),
                    "message": "User registered",
                    "result": {
                        "uuid": uuid,
                        "email": email
                    }
                })
            } else {
                if (err.code == "ER_DUP_ENTRY") {
                    res.send({
                        "code": 400,
                        "requestId": uuidv4(),
                        "time": unixTimestamp(),
                        "message": "User already exists",
                        "result": null
                    })
                } else {
                    res.send({
                        "code": 400,
                        "requestId": uuidv4(),
                        "time": unixTimestamp(),
                        "message": "Registration failed",
                        "result": null
                    })
                }
            }
        })
    })
})

app.post('/api/v1/service', (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err
        console.log(`Connected as id ${connection.threadId}`)
        const { name, uid } = req.body;
        const uuid = uuidv4();

        connection.query("INSERT INTO `auth_service`(`uuid`,`name`,`uid`) VALUES (?, ?, ?);", [uuid, name, uid], (err) => {
            connection.release;
            if (!err) {
                res.send({
                    "code": 200,
                    "requestId": uuidv4(),
                    "time": unixTimestamp(),
                    "message": "Service registered",
                    "result": {
                        "uuid": uuid,
                        "name": name
                    }
                })
            } else {
                res.send({
                    "code": 400,
                    "requestId": uuidv4(),
                    "time": unixTimestamp(),
                    "message": "Service registration failed",
                    "result": null
                })
            }
        })
    })
})

app.post('/api/v1/api', (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err
        console.log(`Connected as id ${connection.threadId}`)
        const { uid } = req.body;
        const uuid = uuidv4();

        connection.query("INSERT INTO `auth_api`(`key`,`uid`) VALUES (?, ?);", [uuid, uid], (err) => {
            connection.release;
            if (!err) {
                res.send({
                    "code": 200,
                    "requestId": uuidv4(),
                    "time": unixTimestamp(),
                    "message": "API Created",
                    "result": {
                        "key": uuid
                    }
                })
            } else {
                res.send({
                    "code": 400,
                    "requestId": uuidv4(),
                    "time": unixTimestamp(),
                    "message": "API creation failed",
                    "result": null
                })
            }
        })
    })
})

app.post('/api/v1/access', (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err
        console.log(`Connected as id ${connection.threadId}`)
        const { uid, sid } = req.body;
        const uuid = uuidv4();

        connection.query("INSERT INTO `auth_access`(`uid`,`sid`,`uuid`) VALUES (?,?,?);", [uid, sid, uuid], (err) => {
            connection.release;
            if (!err) {
                res.send({
                    "code": 200,
                    "requestId": uuidv4(),
                    "time": unixTimestamp(),
                    "message": "Access granted",
                    "result": {
                        "accessId": uuid
                    }
                })
            } else {
                console.log(err);
                res.send({
                    "code": 400,
                    "requestId": uuidv4(),
                    "time": unixTimestamp(),
                    "message": "Failed to add access",
                    "result": null
                })
            }
        })
    })
})


app.post('/api/v1/checkapi', (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err
        console.log(`Connected as id ${connection.threadId}`)
        const { uid, api } = req.body;

        (async () => {
            const isValidApi = checkApi(uid, api);
            isValidApi.then((result) => {
                if (result != null && result.is_active == 1) {
                    res.send({
                        "code": 200,
                        "requestId": uuidv4(),
                        "time": unixTimestamp(),
                        "message": "API is valid",
                        "result": {
                            "api": api
                        }
                    })
                } else {
                    res.send({
                        "code": 200,
                        "requestId": uuidv4(),
                        "time": unixTimestamp(),
                        "message": "API is Invalid",
                        "result": null
                    })
                }
            })
        })()
    })
})

app.post('/api/v1/checkservice', (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err
        console.log(`Connected as id ${connection.threadId}`)
        const { sid, api } = req.body;

        (async () => {
            const isValidApi = checkService(sid, api);
            isValidApi.then((result) => {
                if (result != null && result.is_active == 1) {
                    res.send({
                        "code": 200,
                        "requestId": uuidv4(),
                        "time": unixTimestamp(),
                        "message": "Service and API is valid",
                        "result": {
                            "api": api
                        }
                    })
                } else {
                    res.send({
                        "code": 200,
                        "requestId": uuidv4(),
                        "time": unixTimestamp(),
                        "message": "Service and API is Invalid",
                        "result": null
                    })
                }
            })
        })()
    })
})

app.post('/api/v1/login', (req, res) => {
    pool.getConnection((err, connection) => {
        if (err) throw err
        console.log(`Connected as id ${connection.threadId}`)
        const { email, password, api, service } = req.body;
        const uuid = uuidv4();

        (async () => {
            insertIp(req.ip);
            const isValidApi = checkService(service, api);
            isValidApi.then((result) => {
                if (result != null && result.is_active == 1) {
                    const hasAccess = checkAccess(email, service);

                    hasAccess.then((access) => {
                        if (access != null && access.has_access == 1) {

                            const login = checkLoginPassword(email, password);

                            login.then((user) => {
                                if (user != null && checkPassword(password, user.password)) {

                                    const u = {
                                        "id": user.id,
                                        "uuid": user.uuid,
                                        "email": user.email,
                                        "isBanned": user.is_banned,
                                        "createdAt": user.created_at,
                                    }

                                    insertHistory(uuid, user.id, service, req.ip);

                                    const accessToken = jwt.sign(u, process.env.ACCESS_TOKEN_SECRET);

                                    res.send({
                                        "code": 200,
                                        "requestId": uuidv4(),
                                        "time": unixTimestamp(),
                                        "message": "Login successfully",
                                        "result": {
                                            "accessToken": accessToken
                                        }
                                    });
                                } else {
                                    res.send({
                                        "code": 400,
                                        "requestId": uuidv4(),
                                        "time": unixTimestamp(),
                                        "message": "Invalid password",
                                        "result": null
                                    });
                                }
                            })

                        } else {
                            res.send({
                                "code": 200,
                                "requestId": uuidv4(),
                                "time": unixTimestamp(),
                                "message": "Access is not valid for service",
                                "result": null
                            })
                        }
                    })
                } else {
                    res.send({
                        "code": 200,
                        "requestId": uuidv4(),
                        "time": unixTimestamp(),
                        "message": "Invalid service or api",
                        "result": null
                    })
                }
            })
        })()
    })
})

if (process.env.NODE_ENV == "production") {
    app.listen()
} else {
    app.listen(port, () => { })
}