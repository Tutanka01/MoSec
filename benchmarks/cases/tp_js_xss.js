// BENCHMARK CASE: True Positive — XSS via innerHTML in Express.js
// CWE-79 | Source: req.query | Sink: element.innerHTML (via HTTP response)
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;
    // User input directly assigned to innerHTML in the response body
    const html = `
        <html><body>
          <div id="result"></div>
          <script>
            document.getElementById('result').innerHTML = '${query}';
          </script>
        </body></html>`;
    res.send(html);
});

app.listen(3000);
