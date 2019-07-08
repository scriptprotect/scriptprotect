ScriptProtect
================

This repository contains the code for our [AsiaCCS 2019 paper: "ScriptProtect: Mitigating Unsafe Third-Party JavaScript Practices"](https://www.tu-braunschweig.de/Medien-DB/ias/pubs/2019-asiaccs.pdf)

How to
-------
For readability, DOMPurify is located in a separate file.
The third-party is simulated via another hostname that also resolves back to 127.0.0.1

Start a web server on port 8000 in this directory, e.g. with `python -m SimpleHTTPServer` (or `python -m http.server` for newer versions).

Visit [index.html](http://localhost:8000/index.html) and open the console in the developer tools, to inspect the blocked and allowed calls.
You can experiment by writing your own code into the console, but note that this code will be allowed by default.
To test the actual blocking, add code to `third_party.js`.

Cite this work
-------
```
@inproceedings{musch2019scriptprotect,
    author={Musch, Marius and Steffens, Marius and Roth, Sebastian and Stock, Ben and Johns, Martin},
    title={ScriptProtect: Mitigating Unsafe Third-Party JavaScript Practices},
    booktitle={AsiaCCS},
    year={2019}
}
```

Abstract
-------
The direct client-side inclusion of cross-origin JavaScript resources
in Web applications is a pervasive practice to consume third-party
services and to utilize externally provided libraries. The downside of
this practice is that such external code runs in the same context and
with the same privileges as the first-party code. Thus, all potential
security problems in the code directly affect the including site. To
explore this problem, we present an empirical study which shows
that more than 25% of all sites affected by Client-Side Cross-Site
Scripting are only vulnerable due to a flaw in the included third-party code.
Motivated by this finding, we propose ScriptProtect, a nonintrusive transparent protective measure to address security issues introduced by external script resources. ScriptProtect automatically strips third-party code from the ability to conduct unsafe string-to-code conversions. Thus, it effectively removes the
root-cause of Client-Side XSS without affecting first-party code
in this respective. As ScriptProtect is realized through a lightweight JavaScript instrumentation, it does not require changes to
the browser and only incurs a low runtime overhead of about 6%.
We tested its compatibility on the Alexa Top 5,000 and found that
30% of these sites could benefit from ScriptProtect’s protection
today without changes to their application code.
