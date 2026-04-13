const express = require('express');
const path = require('path');
const app = express();
const port = process.env.WATCHTOWER_UI_PORT || 8080;

const fs = require('fs');
const apiKey = process.env.WATCHTOWER_API_KEY || "WATCHTOWER_DEFAULT_KEY";
const apiPort = process.env.WATCHTOWER_API_PORT || "4040";

app.get('/watchtower.html', (req, res) => {
    let html = fs.readFileSync(path.join(__dirname, 'watchtower.html'), 'utf8');
    html = html.replaceAll('YOUR_SECRET_API_KEY_HERE', apiKey);
    html = html.replaceAll('YOUR_SECRET_API_PORT_HERE', apiPort);
    res.send(html);
});

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.redirect('/watchtower.html');
});

app.listen(port, () => {
    console.log(`[Watchtower V2 Glass Pane] UI Server listening on http://localhost:${port}`);
});
