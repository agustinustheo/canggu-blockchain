// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="introduction.html">Introduction</a></li><li class="chapter-item expanded affix "><a href="credits.html">Credits and authorship</a></li><li class="chapter-item expanded affix "><li class="part-title">Background</li><li class="chapter-item expanded "><a href="background/canggu-v1.html"><strong aria-hidden="true">1.</strong> What Canggu set out to do</a></li><li class="chapter-item expanded "><a href="background/polkadot-sdk-primer.html"><strong aria-hidden="true">2.</strong> The Polkadot SDK in ten minutes</a></li><li class="chapter-item expanded "><a href="background/crypto-primer.html"><strong aria-hidden="true">3.</strong> Post-quantum cryptography and zero knowledge, briefly</a></li><li class="chapter-item expanded "><a href="background/architecture.html"><strong aria-hidden="true">4.</strong> The big picture</a></li><li class="chapter-item expanded affix "><li class="part-title">Run it yourself</li><li class="chapter-item expanded "><a href="getting-started/requirements.html"><strong aria-hidden="true">5.</strong> Requirements</a></li><li class="chapter-item expanded "><a href="getting-started/build-and-run.html"><strong aria-hidden="true">6.</strong> Build and start a chain</a></li><li class="chapter-item expanded "><a href="getting-started/cli.html"><strong aria-hidden="true">7.</strong> Use the canggu command line</a></li><li class="chapter-item expanded "><a href="getting-started/tests.html"><strong aria-hidden="true">8.</strong> Run the tests</a></li><li class="chapter-item expanded affix "><li class="part-title">How each part works</li><li class="chapter-item expanded "><a href="features/post-quantum-accounts.html"><strong aria-hidden="true">9.</strong> Post-quantum accounts</a></li><li class="chapter-item expanded "><a href="features/dag-ordering.html"><strong aria-hidden="true">10.</strong> Transactions that wait for each other</a></li><li class="chapter-item expanded "><a href="features/sealed-ordering.html"><strong aria-hidden="true">11.</strong> Sealed ordering against front-running</a></li><li class="chapter-item expanded "><a href="features/zk-proofs.html"><strong aria-hidden="true">12.</strong> Zero-knowledge proofs: Groth16 and SP1</a></li><li class="chapter-item expanded "><a href="features/signature-compression.html"><strong aria-hidden="true">13.</strong> Signature compression with a zkVM</a></li><li class="chapter-item expanded "><a href="features/payroll.html"><strong aria-hidden="true">14.</strong> Parallel payroll</a></li><li class="chapter-item expanded "><a href="features/gpu.html"><strong aria-hidden="true">15.</strong> GPU verification with Apple Metal</a></li><li class="chapter-item expanded "><a href="features/finality.html"><strong aria-hidden="true">16.</strong> Sub-second finality</a></li><li class="chapter-item expanded affix "><li class="part-title">Results and lessons</li><li class="chapter-item expanded "><a href="results/numbers.html"><strong aria-hidden="true">17.</strong> All the numbers</a></li><li class="chapter-item expanded "><a href="results/corrections.html"><strong aria-hidden="true">18.</strong> What the original design got wrong</a></li><li class="chapter-item expanded "><a href="results/rand-protocol.html"><strong aria-hidden="true">19.</strong> Lessons from Rand Protocol</a></li><li class="chapter-item expanded "><a href="results/why-polkadot-sdk.html"><strong aria-hidden="true">20.</strong> Why the Polkadot SDK made this possible</a></li><li class="chapter-item expanded "><a href="results/limitations.html"><strong aria-hidden="true">21.</strong> Limitations and open problems</a></li><li class="chapter-item expanded affix "><li class="part-title">Appendix</li><li class="chapter-item expanded "><a href="appendix/repository-map.html"><strong aria-hidden="true">22.</strong> Repository map</a></li><li class="chapter-item expanded "><a href="appendix/glossary.html"><strong aria-hidden="true">23.</strong> Glossary</a></li><li class="chapter-item expanded "><a href="appendix/references.html"><strong aria-hidden="true">24.</strong> References</a></li><li class="chapter-item expanded "><a href="appendix/about-these-docs.html"><strong aria-hidden="true">25.</strong> About these docs</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
