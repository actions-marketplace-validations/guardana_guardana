"""The pack's own control catalogue, and the public entries its rules map to beside it.

The catalogue is registered through `guardana.taxonomies` before any rule loads, which
is what lets the YAML rule write `taxonomy: [REF-2]`. The OWASP entries are written out
in full because the supported surface offers no lookup; the suite checks that each one
equals what the engine's own catalogue resolves.
"""

from guardana.core import TaxonomyRef

SCHEME = "REFERENCE-CONTROLS"

PINNED_DEPENDENCIES = TaxonomyRef(
    scheme=SCHEME,
    id="REF-1",
    title="Every dependency is pinned to one version",
)
CONFIDENTIAL_NAMES = TaxonomyRef(
    scheme=SCHEME,
    id="REF-2",
    title="Internal names stay inside the organisation",
)

CONTROLS = (PINNED_DEPENDENCIES, CONFIDENTIAL_NAMES)
"""Every control the catalogue registers."""

OWASP_LLM02_2025 = TaxonomyRef(
    scheme="OWASP-LLM",
    id="LLM02",
    title="Sensitive Information Disclosure",
    edition="2025",
    rank=2,
)
OWASP_LLM03_2025 = TaxonomyRef(
    scheme="OWASP-LLM",
    id="LLM03",
    title="Supply Chain",
    edition="2025",
    rank=3,
)
