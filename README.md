ScriptProtect
================

Implementation for our paper. For readability, DOMPurify is located in a separate file.
The third-party is simulated via another hostname that also resolves back to 127.0.0.1

How to
-------

Start a web server on port 8000 in this directory, e.g. with `python -m SimpleHTTPServer` (or `python -m http.server` for newer versions).

Visit [index.html](http://localhost:8000/index.html) and open the console in the developer tools, to inspect the blocked and allowed calls.
You can experiment by writing your own code into the console, but note that this code will be allowed by default.
To test the actual blocking, add code to `third_party.js`.
