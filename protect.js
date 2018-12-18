(function () {

    //If enabled, does not block anything
    const reportOnly = false;

    //If enabled, exposes unsafe variants of APIs and properties (for new applications)
    const createUnsafeVariant = false;

    //If enabled, checks the stack trace to decide if calls are allowed (for legacy applications)
    const inspectStacktrace = !createUnsafeVariant;

    //Vastly increases compatibility while only slightly affecting security (see paper for reasoning)
    const htmlSinksOnly = inspectStacktrace;

    //TODO for use in production: send object to backend, e.g. to store it in a database
    const logger = console.log;

    //JavaScript statements that are considered no-operations and thus harmless
    const whitelistedJS = ["", "0", "void(0)", "void 0", "return false", "//"];

    //Optional: Do not run protection in iframes (Useful if proxy injects it everywhere)
    if (window.self !== window.top) { return; }

    function saveData(obj) {
        obj.host = location.hostname;
        //Was blocked, if the HTML was sanitized and something removed (removedCount > 0) or was a JS or URI sink (type > 1)
        //AND
        //stack trace based inspection is used for compatibility and the action was not initiated by the first-party (!isAllowed)
        if ((obj.removedCount > 0 || obj.type > 1) && !isAllowed({allSame: obj.allSame, topSame: obj.topSame})) {
            logger("BLOCKED", obj);
        }
        else {
            logger("ALLOWED", obj);
        }
    }

    //Get formatted stacktrace
    function getStack() {
        let result = "";
        let stack = Error().stack;
        let lines = stack.split("\n");
        //Skip calls inside this script
        for (let i = 3; i < lines.length; i++) {
            result += lines[i].trim() + " <- ";
        }
        return result.substring(0, result.length - 4);
    }

    //Check if DOMPurify is in the stack
    function isIgnored() {
        let stack = Error().stack;
        return /purify(\.min)?\.js/.test(stack);
        //XXX If the script is artificially injected, e.g. during the evaluation, then use this check instead
        //return /Function\.S\.sanitize/.test(stack);
    }

    //Allow depending on policy and stacktrace
    function isAllowed(origins) {
        return inspectStacktrace && origins.allSame;
    }

    //Check if whole stack or top is same origin
    function getOrigins() {
        let parser = document.createElement("a");
        let re = /(https?:\/\/.+?):\d+:\d+/g;
        let stack = Error().stack;

        let urls = stack.match(re);
        if (urls && urls.length > 0) {
            //Use last entry and extract its hostname from URL
            parser.href = urls[urls.length - 1];
            //Compare accoring to our notion of extended parties
            let same = sameParty(location.hostname, parser.hostname);
            return {allSame: same, topSame: same, offending: []};
        }
        return {allSame: true, topSame: true, offending: []};
    }

    //Check if two hosts should be considered the same
    function sameParty(host1, host2) {
        //Always remove www. so that api.example.com is obvious subdomain of www.example.com
        if (host1.startsWith("www.")) {
            host1 = host1.slice(4);
        }
        if (host2.startsWith("www.")) {
            host2 = host2.slice(4);
        }
        //Same domain, subdomain or parent domain
        if (host1 == host2 || host1.endsWith("." + host2) || host2.endsWith("." + host1)) {
            return true;
        }
        return false;
    }

    function getHost(url) {
        let parser = document.createElement("a");
        parser.href = url;
        return parser.hostname;
    }

    function getHostFromScript(element) {
        if (!element.src) {
            return;
        }
        return getHost(element.src);
    }

    //Test if an element has an event handler
    function hasEventHandler(element) {
        for (let attr of element.attributes) {
            if (attr.name.startsWith("on")) {
                return true;
            }
        }
        return false;
    }

    //Only no-ops like void
    function isSafeJS(code) {
        code = code.replace(/;/g, "").trim();
        return whitelistedJS.includes(code);
    }

    //Only no-ops like void
    function isSafeJSURI(uri) {
        let code = uri.replace("javascript:", "");
        return isSafeJS(code);
    }

    //No src, no event handlers, only no-ops/empty code
    function isSafeScript(script) {
        return !script.src  && !hasEventHandler(script) && isSafeJS(script.text);
    }

    //No JS-URI, no srcdoc, no event handlers
    function isSafeIframe(iframe) {
        let isSafeSrc = true;
        if (iframe.src) {
            isSafeSrc = !iframe.src.startsWith("javascript:") || isSafeJSURI(iframe.src);
        }
        return isSafeSrc && !iframe.srcdoc && !hasEventHandler(iframe);
    }

    //Count only removed elements that could lead to code execution
    function countRemoved() {
        let count = 0;
        let items = [];
        for (let r of DOMPurify.removed) {
            let item;
            let ele = r.element;
            let attr = r.attribute;
            let from = r.from;

            if (ele) {
                let host = getHostFromScript(ele);
                //Scripts
                if (ele.localName == "script" && !isSafeScript(ele)) {
                    item = {element: ele.localName, host: host, value: ele.outerHTML};
                }
                //Iframes
                else if (ele.localName == "iframe" && !isSafeIframe(ele)) {
                    item = {element: ele.localName, host: host, value: ele.outerHTML};
                }
            }
            else if (attr) {
                //Event handlers
                if (attr.name.startsWith("on") && !isSafeJS(attr.value)) {
                    item = {element: from.localName, attribute: attr.name, value: attr.value};
                }
            }

            if (!item) {
                continue;
            }

            //Only add unique items
            let seen = false;
            for (let old of items) {
                if (old.element == item.element && old.host == item.host && old.attribute == item.attribute && old.value == item.value) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                count++;
                items.push(item);
            }
        }
        return {count: count, items: items};
    }

    //Called by all HTML sinks
    function interceptHTML(sink, code, ele) {
        //Do not log if the DOM manipulation was caused by DOMPurify
        if (isIgnored()) {
            return code;
        }

        let removed;
        let originalCode = code;
        let element = ele && ele.nodeName ? ele.nodeName.toLowerCase() : undefined;
        let stack = getStack();
        let origins = getOrigins();

        if (isAllowed(origins)) {
            //Report anyway so that we can see the allowed cases
            saveData({type: 1, sink: sink, code: code, element: element, stack: stack, allSame: origins.allSame, topSame: origins.topSame});
            //Return unsanitized code, as we trust the parties in the stacktrace
            return code;
        }

        //Sanitize code with DOMPurify
        //XXX Without WHOLE_DOCUMENT elements might be missing from DOMPurify.removed
        DOMPurify.sanitize(code, {WHOLE_DOCUMENT: true, SANITIZE_DOM: false});
        removed = countRemoved();
        //Only use the santizied code if we found something leading to script execution, otherwise just use the original
        //TODO Use DomPurify's uponSanitizeElement instead
        if (removed.count > 0) {
            //However, we need to return the sanitized value without WHOLE_DOCUMENT
            code = DOMPurify.sanitize(code, {SANITIZE_DOM: false});
        }
        saveData({type: 1, sink: sink, code: originalCode, element: element, stack: stack, allSame: origins.allSame, topSame: origins.topSame,
            offending: origins.offending, removedCount: removed.count, removedItems: removed.items});

        if (reportOnly) {
            return originalCode;
        }
        return code;
    }

    //Called by all JS/URL sinks
    function intercept(sink, code, ele) {
        let type = sink == "src" ? 3 : 2;
        if (code) {
            code = typeof code == "string" ? code : code.toString();
        }
        let element = ele ? ele.nodeName.toLowerCase() : undefined;
        let stack = getStack();
        let origins = getOrigins();
        saveData({type: type, sink: sink, code: code, element: element, stack: stack, allSame: origins.allSame, topSame: origins.topSame, offending: origins.offending});

        //Result is only executed if we return true
        return reportOnly || isAllowed(origins);
    }

    /*
     * Wrapped HTML sinks below
     */

    //document.write, document.writeln
    (function () {
        let old = {};
        function wrap(name) {
            old[name] = document[name];
            if (createUnsafeVariant) {
                document["unsafe_" + name] = old[name];
            }
            document[name] = function(arg) {
                for (let i = 0; i < arguments.length; i++) { arguments[i] = interceptHTML(name, arguments[i]); }
                old[name].call(document, ...arguments);
            };
        }
        wrap("write");
        wrap("writeln");
    })();

    //Element.insertAdjacentHTML
    (function() {
        let old = Element.prototype.insertAdjacentHTML;
        if (createUnsafeVariant) {
            Element.prototype["unsafe_insertAdjacentHTML"] = old;
        }
        Element.prototype.insertAdjacentHTML = function() {
            if (arguments.length == 2) {
                arguments[1] = interceptHTML("adjacentHTML", arguments[1], this);
            }
            return old.call(this, ...arguments);
        }
    })();

    //Element.innerHTML, Element.outerHTML
    //HTMLIFrameElement.srcdoc
    //HTMLButtonElement.value
    (function () {
        var old = {};
        function wrap(ele, attr) {
            let key = ele.name + "." + attr;
            old[key] = Object.getOwnPropertyDescriptor(ele.prototype, attr).set;
            if (createUnsafeVariant) {
                Object.defineProperty(ele.prototype, "unsafe_" + attr, {
                    set: old[key]
                });
            }
            Object.defineProperty(ele.prototype, attr, {
                set: function (val) {
                    val = interceptHTML(attr, val, this);
                    old[key].call(this, val);
                }
            });
        }
        wrap(Element, "innerHTML");
        wrap(Element, "outerHTML");
        wrap(HTMLIFrameElement, "srcdoc");
    })();

    //Range.createContextualFragment
    (function() {
        let range = document.createRange().__proto__;
        let old = range.createContextualFragment;
        if (createUnsafeVariant) {
            range["unsafe_createContextualFragment"] = old;
        }
        range.createContextualFragment = function() {
            if (arguments.length > 0) {
                arguments[0] = interceptHTML("contextualFragment", arguments[0]);
            }
            return old.call(this, ...arguments);
        }
    })();

    /*
     * All three sinks mixed
     */

    //Element.setAttribute
    (function() {
        let old = Element.prototype.setAttribute;
        if (createUnsafeVariant) {
            Element.prototype["unsafe_setAttribute"] = old;
        }
        if (htmlSinksOnly) {
            Element.prototype.setAttribute = function() {
                let name = this.nodeName.toLowerCase();
                let attr = arguments[0];
                let val = arguments[1];
                if (name == "HTMLIFrameElement" && attr == "srcdoc") {
                    arguments[1] = interceptHTML(attr, val, this);
                    old.call(this, ...arguments);
                }
                else {
                    //Boring attribute, call original without interception
                    old.call(this, ...arguments);
                }
            }
        }
        else {
            Element.prototype.setAttribute = function() {
                let name = this.nodeName.toLowerCase();
                if (name == "script") name = "HTMLScriptElement";
                if (name == "iframe") name = "HTMLIFrameElement";
                let attr = arguments[0];
                let val = arguments[1];
                let key = name + "." + attr;
                if (attr == "src" && (name == "HTMLScriptElement" || (name == "HTMLIFrameElement" && val && val.startsWith("javascript:")))) {
                    if (intercept(attr, val, this)) {
                        old.call(this, ...arguments);
                    }
                }
                else if (name == "HTMLIFrameElement" && attr == "srcdoc") {
                    arguments[1] = interceptHTML(attr, val, this);
                    old.call(this, ...arguments);
                }
                else {
                    //Boring attribute, call original without interception
                    old.call(this, ...arguments);
                }
            }
        }
    })();

    //jQuery .append and .html will happily add new scripts to the HEAD (or eval in older versions)
    //Prevent that for third parties, too
    //.before, .after and .prepend are already blocked via our innerHTML wrapper
    (function() {
        let j;
        let old = {};
        function wrap(obj, name) {
            old[name] = obj.prototype[name];
            if (createUnsafeVariant) {
                obj.prototype["unsafe_" + name] = old[name];
            }
            obj.prototype[name] = function(arg) {
                for (let i = 0; i < arguments.length; i++) {
                    if (typeof arguments[i] == "string") {
                        arguments[i] = interceptHTML("jQuery." + name, arguments[i]);
                    }
                }
                old[name].call(this, ...arguments);
            };
        }
        Object.defineProperty(window,'jQuery',{
            get: function() {
                return j;
            },
            set: function(val){
                console.log('jQuery detected');
                wrap(val, "append");
                j = val;
            },
        });
    })()

    if (htmlSinksOnly) {
        return;
    }

    /*
     * Wrapped JS sinks below
     */

    //Function constructor
    (function () {
        let old = Function;
        Function = function() {
            if (arguments.length > 0) {
                let last = arguments[arguments.length - 1];
                if (intercept("Function", last)) {
                    return old(...arguments);
                }
            }
        }
        //Set prototype like in the original
        Function.prototype = old.prototype
        //Function constructor should always be itself
        Function.constructor = Function;
    })();

    //execScript
    //setTimeout, setInterval, setImmediate
    (function () {
        let old = {};
        function wrap(name) {
            //Check if function even exists
            if (!window[name]) { return; }
            old[name] = window[name];
            if (createUnsafeVariant) {
                window["unsafe_" + name] = old[name];
            }
            window[name] = function(arg) {
                //Log only if there is a string to code conversion
                if (typeof arguments[0] != "string" || intercept(name, arguments[0])) {
                    old[name].call(window, ...arguments);
                }
            };
        }
        wrap("setTimeout");
        wrap("setInterval");
        //Following two only exist in IE
        wrap("setImmediate");
        wrap("execScript");
    })();

    //HTMLScriptElement.text, .textContent, .innerText
    (function () {
        var old = {};
        function wrap(ele, attr, from) {
            from = from == undefined ? ele : from;
            let key = ele.name + "." + attr;
            old[key] = Object.getOwnPropertyDescriptor(from.prototype, attr).set;
            if (createUnsafeVariant) {
                Object.defineProperty(from.prototype, "unsafe_" + attr, {
                    set: old[key]
                });
            }
            Object.defineProperty(ele.prototype, attr, {
                configurable: true,
                set: function (val) {
                    if (intercept(attr, val, this)) {
                        old[key].call(this, ...arguments);
                    }
                }
            });
        }
        wrap(HTMLScriptElement, "text");
        //Following two take the property of "parent", but only change it in HTMLScriptElement
        wrap(HTMLScriptElement, "textContent", Node);
        wrap(HTMLScriptElement, "innerText", HTMLElement);
    })();

    /*
     * Wrapped URI sinks below
     */

    //HTMLScriptElement.src
    //HTMLIFrameElement.src
    (function () {
        var old = {};
        function wrap(ele, attr) {
            let key = ele.name + "." + attr;
            old[key] = Object.getOwnPropertyDescriptor(ele.prototype, attr).set;
            if (createUnsafeVariant) {
                Object.defineProperty(ele.prototype, "unsafe_" + attr, {
                    set: old[key]
                });
            }
            Object.defineProperty(ele.prototype, attr, {
                set: function (val) {
                    //IFrame.src is harmless, as long as it is not a JSURI
                    if ((ele.name == "HTMLIFrameElement" && val && !val.startsWith("javascript:")) || intercept(attr, val, this)) {
                        old[key].call(this, ...arguments);
                    }
                }
            });
        }
        wrap(HTMLScriptElement, "src");
        wrap(HTMLIFrameElement, "src");
    })();

})();
