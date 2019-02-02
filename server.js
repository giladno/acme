'use strict';
const express = require('express');
const app = express();

app.use((req, res) => {
    console.log(req.method, req.url, req.headers, req.body, '\n');
    res.json({});
});

app.listen(8888);
