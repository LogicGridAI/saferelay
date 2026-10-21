"""
SafeRelay Python SDK — SafeRelayClient
pip install saferelay

Usage:
    from saferelay import SafeRelayClient
    client = SafeRelayClient(mode="zero-trust")
    safe = client.redact("token AKIAIOSFODNN7EXAMPLE at 10.1.2.3")
    print(safe)        # "token 🔒[AWS_KEY_1] at 🔒[IP_1]"
    print(client.last_detections)  # {"AWS_KEY": 1, "IP": 1}

Pattern parity:
    This module is a faithful Python port of the canonical SafeRelay
    eight-shield DLP engine shared by the Browser Relay extension (dlp.js)
    and the Desktop agent. Pattern taxonomy, regexes, validators, engine
    semantics (definition-order precedence with claimed-span suppression,
    left-to-right numbering, right-to-left application, NFKC + zero-width
    normalisation with offset map, fail-closed on engine error) and the
    exfiltration bulk-threshold block are all mirrored so the CLI/SDK
    produce IDENTICAL redaction output to the browser/desktop engine.

    Eight canonical shields:
        basicProtection / devsec  — API keys, cloud keys, IPs, crypto, env values
        fintech                   — CC/Luhn, SSN, IBAN, global national-ID PII
        corporate                 — DUNS, EIN, VAT
        civic                     — GPS, UNHCR, beneficiary IDs
        gov_cui                   — DoD contract, CAGE, UEI, CUI banners, FedRAMP,
                                    ITAR/EAR/ECCN, DIST markings, REL TO, gov email
        exfiltrationShield        — threshold block (>=3 SSN, >=5 CC, >=20 email)
"""

from __future__ import annotations
import re
import unicodedata
from typing import Callable, Literal, Optional

# ---------------------------------------------------------------------------
# Helper validators (ported from dlp.js)
# ---------------------------------------------------------------------------

_CONTEXT_WINDOW = 100  # chars to scan around a bare 64-hex match


def _is_pure_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]+", s, re.IGNORECASE))


def _is_false_positive_api_match(match: str) -> bool:
    """Filter hex-only Bearer / sk- / pk- tokens (git SHAs, digests, examples).

    Mirrors dlp.js _isFalsePositiveApiMatch (no bare-40-hex short-circuit; that
    branch belongs to AWS_SECRET, not the API-key gate)."""
    lower = str(match).lower()
    if lower.startswith("bearer "):
        t = lower[7:].strip()
        return len(t) >= 16 and _is_pure_hex(t)
    if re.match(r"^(sk|pk)-", match, re.IGNORECASE):
        t = re.sub(r"^(sk|pk)-", "", lower).strip()
        return len(t) >= 16 and _is_pure_hex(t)
    return False


def _luhn_valid(digits_only: str) -> bool:
    if len(digits_only) not in (15, 16):
        return False
    total = 0
    alt = False
    for ch in reversed(digits_only):
        if not ch.isdigit():
            return False
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _v_credit_card(m: str) -> bool:
    digits = re.sub(r"\D", "", m)
    return len(digits) in (15, 16) and _luhn_valid(digits)


def _v_ipv4(m: str) -> bool:
    octets = m.split(".")
    if len(octets) != 4:
        return False
    try:
        ints = [int(o) for o in octets]
    except ValueError:
        return False
    if ints[0] == 127 or ints[0] == 255:
        return False
    return all(0 <= o <= 255 for o in ints)


# ── Degenerate base64 gate (AWS_SECRET) ──────────────────────────────────────
# Reject low-diversity 40-char runs (banner padding, repeats) — never secrets.
# Mirrors dlp.js _isDegenerateBase64Like: < 15 distinct chars.
def _is_degenerate_base64_like(m: str) -> bool:
    return len(set(m)) < 15


def _v_aws_secret_named(m: str) -> bool:
    # dlp.js: !/^[0-9a-f]{40}$/.test(m) && !_isDegenerateBase64Like(m)
    return not bool(re.fullmatch(r"[0-9a-f]{40}", m, re.IGNORECASE)) and not _is_degenerate_base64_like(m)


def _v_aws_secret_raw(m: str) -> bool:
    # dlp.js: !/^[0-9a-fA-F]{40}$/.test(m) && !_isDegenerateBase64Like(m)
    return not bool(re.fullmatch(r"[0-9a-fA-F]{40}", m)) and not _is_degenerate_base64_like(m)


def _v_openai_legacy(m: str) -> bool:
    return not _is_false_positive_api_match(m)


def _v_bearer(m: str) -> bool:
    return not _is_false_positive_api_match(m)


def _v_api_key_catch(m: str) -> bool:
    return not _is_false_positive_api_match(m)


# ── National-ID checksum validators (ported from dlp.js) ─────────────────────

def _v_iban(m: str) -> bool:
    """ISO 7064 mod-97 IBAN check (SR-FP-009)."""
    s = re.sub(r"[\s-]", "", m).upper()
    if len(s) < 15 or len(s) > 34:
        return False
    rearranged = s[4:] + s[:4]
    num = ""
    for ch in rearranged:
        o = ord(ch)
        num += str(o - 55) if 65 <= o <= 90 else ch
    remainder = 0
    for ch in num:
        if not ch.isdigit():
            return False
        remainder = (remainder * 10 + int(ch)) % 97
    return remainder == 1


# Verhoeff tables (Aadhaar, SR-FP-008)
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _v_aadhaar(m: str) -> bool:
    """Verhoeff check-digit validation for Aadhaar (SR-FP-008)."""
    d = re.sub(r"[\s-]", "", m)
    if len(d) != 12 or not d.isdigit():
        return False
    c = 0
    rev = list(reversed(d))
    for i, ch in enumerate(rev):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def _v_cpf(m: str) -> bool:
    """Brazilian CPF two-check-digit validation (SR-FP-010)."""
    d = re.sub(r"\D", "", m)
    if len(d) != 11:
        return False
    if re.fullmatch(r"(\d)\1{10}", d):  # all same digit
        return False
    total = sum(int(d[i]) * (10 - i) for i in range(9))
    r = (total * 10) % 11
    if r >= 10:
        r = 0
    if r != int(d[9]):
        return False
    total = sum(int(d[i]) * (11 - i) for i in range(10))
    r = (total * 10) % 11
    if r >= 10:
        r = 0
    return r == int(d[10])


_TFN_WEIGHTS = [1, 4, 3, 7, 5, 8, 6, 9, 10]


def _v_au_tfn(m: str) -> bool:
    """Australian TFN weighted-sum validation (SR-FP-011)."""
    d = re.sub(r"[\s-]", "", m)
    if len(d) not in (8, 9) or not d.isdigit():
        return False
    weights = _TFN_WEIGHTS[:8] if len(d) == 8 else _TFN_WEIGHTS
    total = sum(int(d[i]) * weights[i] for i in range(len(d)))
    return total % 11 == 0


def _v_vat_gb(m: str) -> bool:
    """UK VAT mod-97 (and mod-9755 fallback) checksum (SR-FP-019)."""
    digits = re.sub(r"[A-Za-z\s]", "", m)
    if not re.fullmatch(r"\d{9}(\d{3})?", digits):
        return False
    d = [int(x) for x in digits[:9]]
    W = 8 * d[0] + 7 * d[1] + 6 * d[2] + 5 * d[3] + 4 * d[4] + 3 * d[5] + 2 * d[6]
    CD = d[7] * 10 + d[8]
    return (W + CD) % 97 == 0 or (W + 55 + CD) % 97 == 0


def _v_za_id(m: str) -> bool:
    try:
        month = int(m[2:4])
        day = int(m[4:6])
    except (ValueError, IndexError):
        return False
    return 1 <= month <= 12 and 1 <= day <= 31


def _v_us_green_card(m: str) -> bool:
    upper = m.upper()
    if any(upper.startswith(p) for p in ("LIN", "EAC", "WAC", "SRC", "MSC", "IOE")):
        return True
    if re.fullmatch(r"A\d{8,9}", upper):
        return True
    if re.fullmatch(r"[A-Z]{3}\d{10}", upper):
        return True
    return False


def _v_email(m: str) -> bool:
    return not re.search(r"\.(png|jpg|jpeg|gif|svg|webp|css|js|json|html?)$", m, re.IGNORECASE)


# ---------------------------------------------------------------------------
# BIP-39 wordlist (SEED_PHRASE false-positive gate) — 2048 words, verbatim
# copy of dlp.js _BIP39_SET. Used by _v_seed_* for O(1) membership lookup.
# ---------------------------------------------------------------------------
_BIP39_SET = frozenset({
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford",
    "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology",
    "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect",
    "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away",
    "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach",
    "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli",
    "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer",
    "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon",
    "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic",
    "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock",
    "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common",
    "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
    "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
    "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial",
    "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
    "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger",
    "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
    "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial",
    "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice",
    "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
    "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document",
    "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop",
    "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
    "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit",
    "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
    "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact",
    "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase",
    "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust",
    "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
    "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame",
    "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
    "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever",
    "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash",
    "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
    "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury",
    "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
    "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass",
    "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good",
    "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
    "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess",
    "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy",
    "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip",
    "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope",
    "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
    "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea",
    "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
    "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict",
    "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island",
    "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
    "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just",
    "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
    "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder",
    "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal",
    "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
    "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list",
    "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
    "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics",
    "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask",
    "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
    "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge",
    "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile",
    "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply",
    "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve",
    "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number",
    "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit",
    "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
    "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output",
    "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
    "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
    "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet",
    "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
    "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
    "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice",
    "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property",
    "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
    "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter",
    "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
    "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven",
    "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely",
    "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
    "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal",
    "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
    "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket",
    "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
    "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon",
    "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
    "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap",
    "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle",
    "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle",
    "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill",
    "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
    "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff",
    "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare",
    "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
    "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
    "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool",
    "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
    "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny",
    "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol",
    "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
    "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term",
    "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny",
    "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
    "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado",
    "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick",
    "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
    "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin",
    "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
    "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil",
    "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor",
    "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
    "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual",
    "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
    "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash",
    "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
    "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip",
    "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
    "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word",
    "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo",
})


def _valid_seed_phrase(m: str, expected_count: int) -> bool:
    """Mirrors dlp.js _validSeedPhrase: exact word count, every word 3-8 chars
    and in the BIP-39 wordlist."""
    words = m.strip().split()
    if len(words) != expected_count:
        return False
    return all(3 <= len(w) <= 8 and w in _BIP39_SET for w in words)


def _v_seed_12(m: str) -> bool:
    return _valid_seed_phrase(m, 12)


def _v_seed_24(m: str) -> bool:
    return _valid_seed_phrase(m, 24)


def _v_env_value(value: str) -> bool:
    """Receives the VALUE (group 2) of a KEY=value line. Skip if already
    tokenised or if it starts with a named-key prefix (let the named pattern
    win). Mirrors dlp.js ENV_VALUE negative-lookahead + validate()."""
    v = value.strip()
    if re.match(r"^\[[A-Z_]+_\d+\]", v):
        return False
    if re.match(r"^sk-proj-[a-zA-Z0-9_-]{20,}$", v, re.IGNORECASE):
        return False
    if re.match(r"^sk-ant-[a-zA-Z0-9_-]{10,}$", v, re.IGNORECASE):
        return False
    if re.fullmatch(r"AKIA[0-9A-Z]{16}", v):
        return False
    if re.fullmatch(r"ASIA[0-9A-Z]{16}", v):
        return False
    if re.fullmatch(r"ghp_[a-zA-Z0-9]{20,}", v):
        return False
    if re.fullmatch(r"github_pat_[a-zA-Z0-9_]{20,}", v):
        return False
    if re.fullmatch(r"gh[osux]_[a-zA-Z0-9]{20,}", v):
        return False
    if re.fullmatch(r"xox[bap]-[a-zA-Z0-9-]{10,}", v, re.IGNORECASE):
        return False
    if re.fullmatch(r"AIza[0-9A-Za-z\-_]{35}", v):
        return False
    if re.fullmatch(r"sk_(?:live|test)_[a-zA-Z0-9]{24,}", v):
        return False
    if re.fullmatch(r"pk_(?:live|test)_[a-zA-Z0-9]{24,}", v):
        return False
    if re.fullmatch(r"dckr_pat_[a-zA-Z0-9_-]{20,}", v):
        return False
    if re.fullmatch(r"npm_[a-zA-Z0-9]{36,}", v):
        return False
    if re.fullmatch(r"SK[a-zA-Z0-9]{32,}", v):
        return False
    if re.match(r"^bearer\s+", v, re.IGNORECASE):
        return False
    return True


# ── 64-hex CRYPTO_KEY context gate (ported from dlp.js CRYPTO_KEY validate) ───
_HASH_CTX_RE = re.compile(
    r"sha[-_]?256|sha[-_]?512|checksum|hash|digest|file.?hash|image.?hash|verif",
    re.IGNORECASE,
)
_SECRET_CTX_RE = re.compile(
    r"private.?key|secret|wallet|eth.?private|ethereum.?private|seed|mnemonic|crypto.?key",
    re.IGNORECASE,
)


def _ctx_64_hex(m: re.Match, source: str) -> bool:
    """64-hex: redact unless surrounded by hash context AND no secret context.
    Mirrors dlp.js CRYPTO_KEY validate (hashCtx && !secretCtx => skip)."""
    pos = source.find(m.group(0))
    if pos < 0:
        pos = m.start()
    start = max(0, pos - 60)
    end = pos + len(m.group(0)) + 70
    surrounding = source[start:end].lower()
    hash_ctx = bool(_HASH_CTX_RE.search(surrounding))
    secret_ctx = bool(_SECRET_CTX_RE.search(surrounding))
    if hash_ctx and not secret_ctx:
        return False
    return True


# ---------------------------------------------------------------------------
# Canonical pattern registry — faithful port of dlp.js _DLP_PATTERNS.
# Tuple: (TYPE, group, compiled_regex, validator|None, strategy|context_fn|None)
#   strategy: "preserve_conn"  -> keep g1 (scheme://user:) + g3 (@host), redact g2
#             "preserve_group1" -> keep g1 (label), redact g2 (value)
#   context_fn: callable(match, source) -> bool
# "basic" membership (basicProtection vs devsec gating) is derived from
# _DEVSEC_NON_BASIC below, matching dlp.js _patternEnabled.
# ---------------------------------------------------------------------------

# devsec patterns that are NOT basic (gated by the `devsec` toggle, not
# basicProtection). Mirrors dlp.js basic:false entries.
_DEVSEC_NON_BASIC = {"MAC_ADDRESS", "SOL_ADDRESS", "ETH_PRIVATE_KEY", "CRYPTO_KEY_64HEX"}

_PATTERNS: list = [
    # ── Connection strings (devsec basic) ──────────────────────────────────
    ("CONN_STRING", "devsec", re.compile(
        r"\b([a-z][a-z0-9+.\-]*://[^:/\s@]+:)([^\s]+?)(@[a-zA-Z0-9.\-]+(?::\d+)?(?:[/\s]|$))",
        re.I), None, "preserve_conn"),
    # ── IPv4 (devsec basic) ─────────────────────────────────────────────────
    ("IP", "devsec", re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), _v_ipv4, None),
    # ── Named API keys (devsec basic) ───────────────────────────────────────
    ("OPENAI_KEY", "devsec", re.compile(r"\bsk-proj-[a-zA-Z0-9_-]{20,}\b", re.I), None, None),
    ("OPENAI_KEY", "devsec", re.compile(r"\bsk-(?!proj-|ant-)[a-zA-Z0-9_-]{16,}\b", re.I), _v_openai_legacy, None),
    ("ANTHROPIC_KEY", "devsec", re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{10,}\b", re.I), None, None),
    ("AWS_KEY", "devsec", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None, None),
    ("AWS_KEY", "devsec", re.compile(r"\bASIA[0-9A-Z]{16}\b"), None, None),
    ("AWS_SECRET", "devsec", re.compile(
        r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)"
        r"\s*[=:\"'\s]+[\"']?([A-Za-z0-9/+=]{40})[\"']?"), _v_aws_secret_named, None),
    ("AWS_SECRET", "devsec", re.compile(
        r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), _v_aws_secret_raw, None),
    ("GITHUB_PAT", "devsec", re.compile(r"\bghp_[a-zA-Z0-9]{20,}\b"), None, None),
    ("GITHUB_PAT_FG", "devsec", re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{20,}\b"), None, None),
    ("GITHUB_OAUTH", "devsec", re.compile(r"\bgh[osux]_[a-zA-Z0-9]{20,}\b"), None, None),
    ("SLACK_KEY", "devsec", re.compile(r"\bxox[bap]-[a-zA-Z0-9-]{10,}\b", re.I), None, None),
    ("SLACK_WEBHOOK", "devsec", re.compile(
        r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+"), None, None),
    ("GOOGLE_OAUTH", "devsec", re.compile(r"\b\d{6,}-[a-z0-9]+\.apps\.googleusercontent\.com\b", re.I), None, None),
    ("GOOGLE_OAUTH", "devsec", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"), None, None),
    ("GOOGLE_OAUTH", "devsec", re.compile(r"\b1//[A-Za-z0-9_\-]{10,}\b"), None, None),
    ("STRIPE_KEY", "devsec", re.compile(r"\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b"), None, None),
    ("STRIPE_PK", "devsec", re.compile(r"\bpk_(?:live|test)_[a-zA-Z0-9]{24,}\b"), None, None),
    ("BEARER", "devsec", re.compile(r"\bbearer\s+[a-zA-Z0-9._~+/=-]{16,}\b", re.I), _v_bearer, None),
    ("DOCKER_KEY", "devsec", re.compile(r"\bdckr_pat_[a-zA-Z0-9_-]{20,}\b"), None, None),
    ("NPM_TOKEN", "devsec", re.compile(r"\bnpm_[a-zA-Z0-9]{36,}\b"), None, None),
    ("TWILIO_KEY", "devsec", re.compile(r"\bSK[a-zA-Z0-9]{32,}\b"), None, None),
    ("SENDGRID_KEY", "devsec", re.compile(r"\bSG\.[a-zA-Z0-9_-]{14,}\.[a-zA-Z0-9_-]{22,}\b"), None, None),
    ("API_KEY", "devsec", re.compile(r"\bpk-[a-zA-Z0-9_-]{16,}\b", re.I), _v_api_key_catch, None),
    # ── MAC address (devsec non-basic) ──────────────────────────────────────
    ("MAC_ADDRESS", "devsec", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), None, None),
    # ── Bitcoin / Ethereum / Crypto ─────────────────────────────────────────
    ("BTC_ADDRESS", "devsec", re.compile(r"\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b"), None, None),
    ("BTC_ADDRESS", "devsec", re.compile(r"\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b"), None, None),
    ("BTC_ADDRESS", "devsec", re.compile(r"\bbc1[a-z0-9]{6,87}\b", re.I), None, None),
    ("ETH_ADDRESS", "devsec", re.compile(r"\b0x[a-fA-F0-9]{40}\b"), None, None),
    # CRYPTO_KEY 64-hex (devsec non-basic). Internal type-id CRYPTO_KEY_64HEX
    # used only for the basic/non-basic gate; emitted label is CRYPTO_KEY.
    ("CRYPTO_KEY_64HEX", "devsec", re.compile(r"\b[a-fA-F0-9]{64}\b"), None, _ctx_64_hex),
    ("CRYPTO_KEY", "devsec", re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"), None, None),
    ("GEMINI_KEY", "devsec", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), None, None),
    ("SOL_ADDRESS", "devsec", re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{44}\b"), None, None),
    ("ETH_PRIVATE_KEY", "devsec", re.compile(r"\b0x[a-fA-F0-9]{64}\b"), None, None),
    ("SEED_PHRASE", "devsec", re.compile(r"\b([a-z]{3,8}\s){11}[a-z]{3,8}\b"), _v_seed_12, None),
    ("SEED_PHRASE", "devsec", re.compile(r"\b([a-z]{3,8}\s){23}[a-z]{3,8}\b"), _v_seed_24, None),
    ("PEM_KEY", "devsec", re.compile(r"-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE KEY-----"), None, None),
    # ── ENV_VALUE — label-preserve (devsec basic) ───────────────────────────
    # dlp.js uses a lookbehind on ^KEY= plus a negative lookahead for named
    # prefixes; Python captures (KEY=)(value) and preserves g1, validating g2.
    # Value group is [^\r\n]+ with an explicit end-of-line lookahead (not `.+$`):
    # Python's `.` matches \r (JS `.` does not), and Python's multiline `$`
    # anchors before \n but not before \r — so `.+$` on CRLF input both swallows
    # the CR and mis-anchors. [^\r\n]+(?=\r?\n|$) reproduces the JS match exactly
    # on both LF and CRLF input, leaving the line break intact.
    ("ENV_VALUE", "devsec", re.compile(r"(?m)(^[A-Z][A-Z0-9_]*=)([^\r\n]+)(?=\r?\n|$)"), _v_env_value, "preserve_group1"),

    # ── FinTech / PII ────────────────────────────────────────────────────────
    ("CREDIT_CARD", "fintech", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{3,4}\b"), _v_credit_card, None),
    ("US_SSN", "fintech", re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None, None),
    ("EU_IBAN", "fintech", re.compile(
        r"\b[A-Z]{2}\d{2} ?(?:[A-Z0-9]{4} ?){2,7}[A-Z0-9]{1,4}\b", re.I), _v_iban, None),
    ("EMAIL", "fintech", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), _v_email, None),
    ("UK_NINO", "fintech", re.compile(r"\b[A-Z]{2}\d{6}[A-Z]\b"), None, None),
    # Nigeria — context-aware (labeled). Must precede bare NG/DE patterns.
    ("NG_BVN", "fintech", re.compile(
        r"(\b(?:BVN|Bank[\s-]?Verification(?:[\s-]?(?:Number|No|#))?)\s*[:#-]?\s*)(\d{11})\b", re.I),
        None, "preserve_group1"),
    ("NG_NIN", "fintech", re.compile(
        r"(\b(?:NIN|National[\s-]?(?:Identification|Identity|ID)(?:[\s-]?(?:Number|No|#))?)\s*[:#-]?\s*)(\d{11})\b", re.I),
        None, "preserve_group1"),
    # DoD ID / EDIPI — 10-digit labeled (gov_cui). Must precede NG_BANK.
    ("DOD_ID", "gov_cui", re.compile(
        r"(\b(?:DoD\s*ID|EDIPI|CAC\s*(?:ID|Number)?|DoD\s*(?:ID\s*)?(?:Number|No|#))\s*[:#-]?\s*)(\d{10})\b", re.I),
        None, "preserve_group1"),
    ("NG_BANK", "fintech", re.compile(r"\b\d{10}\b"), None, None),
    ("NG_PHONE", "fintech", re.compile(r"\b0[789][01]\d{8}\b"), None, None),
    ("NG_NIN", "fintech", re.compile(r"\b(?!0[789][01]\d{8})\d{11}\b"), None, None),
    ("CA_SIN", "fintech", re.compile(r"\b[1-79]\d{2}-\d{3}-\d{3}\b"), None, None),
    # India Aadhaar: (?<!-) + (?!-[0-9a-fA-F]) guard against UUID/hex tails.
    ("IN_AADHAAR", "fintech", re.compile(
        r"(?<!-)\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b(?!-[0-9a-fA-F])"), _v_aadhaar, None),
    ("IN_PAN", "fintech", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), None, None),
    ("ZA_ID", "fintech", re.compile(r"\b\d{13}\b"), _v_za_id, None),
    ("AU_TFN", "fintech", re.compile(r"\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b"), _v_au_tfn, None),
    ("BR_CPF", "fintech", re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), _v_cpf, None),
    ("SG_NRIC", "fintech", re.compile(r"\b[STFG]\d{7}[A-Z]\b"), None, None),
    ("DE_TAX_ID", "fintech", re.compile(r"\b[1-9]\d{10}\b"), None, None),
    ("US_GREEN_CARD", "fintech", re.compile(r"\b[A-Z]{2,3}\d{9,10}\b"), _v_us_green_card, None),

    # ── Corporate identity ───────────────────────────────────────────────────
    ("DUNS", "corporate", re.compile(
        r"(?:D[-\s]?U[-\s]?N[-\s]?S|D&B|Dun\s*&\s*Bradstreet)"
        r"[^0-9]{0,50}(\d{2}-\d{3}-\d{4}|\d{9})", re.I), None, None),
    ("EIN", "corporate", re.compile(
        r"\b(?:EIN|Tax\s*ID|Federal\s*Tax\s*ID)[^0-9]{0,20}(\d{2}-\d{7})\b", re.I), None, None),
    ("VAT_EU", "corporate", re.compile(
        r"\b(ATU\d{8}|BE0\d{9}|BG\d{9,10}|CY\d{8}L|CZ\d{8,10}"
        r"|DE\d{9}|DK\d{8}|EE\d{9}|EL\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]"
        r"|FI\d{8}|FR[A-Z0-9]{2}\d{9}|HR\d{11}|HU\d{8}"
        r"|IE\d{7}[A-Z]{1,2}|IT\d{11}|LT\d{9,12}|LU\d{8}|LV\d{11}"
        r"|MT\d{8}|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|RO\d{2,10}"
        r"|SE\d{12}|SI\d{8}|SK\d{10})\b"), None, None),
    ("GB_VAT", "corporate", re.compile(
        r"\bGB ?\d{3} ?\d{4} ?\d{2}(?: ?\d{3})?\b", re.I), _v_vat_gb, None),

    # ── Mission & Civic ──────────────────────────────────────────────────────
    ("GPS_COORDS", "civic", re.compile(
        r"\b(-?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)),"
        r"\s*(-?(?:1[0-7]\d(?:\.\d+)?|(?:[1-9]?\d(?:\.\d+)?)|180(?:\.0+)?))\b"), None, None),
    ("UNHCR_ID", "civic", re.compile(
        r"\b(?:UNHCR[-\s]?(?:ID|Reg(?:istration)?)?[-\s#:]*)?"
        r"([A-Z]{3}-\d{2}-\d{6,8}C?\d?)\b", re.I), None, None),
    ("DONOR_ID", "civic", re.compile(
        r"\b(?:Donor|Beneficiary|Bene|Case|Client|Member|Ref)"
        r"[-\s]?(?:ID|No|#|Number|Code)[-\s:]*([A-Z0-9]{4,16})\b", re.I), None, None),

    # ── Gov / CUI Shield ─────────────────────────────────────────────────────
    ("CUI_MARKING", "gov_cui", re.compile(r"\bCONTROLLED\s+UNCLASSIFIED\s+INFORMATION\b", re.I), None, None),
    ("CUI_BANNER", "gov_cui", re.compile(r"\bCUI(?:/\/[A-Z0-9][A-Z0-9-]*)+"), None, None),
    ("DOD_CONTRACT", "gov_cui", re.compile(r"\b[A-Z][A-Z0-9]{5}-[0-9]{2}-[A-Z]-[0-9]{4,7}\b"), None, None),
    ("CAGE_CODE", "gov_cui", re.compile(r"(?:CAGE\s*(?:Code|#|Number)?)\s*[:#-]?\s*[A-Z0-9]{5}\b", re.I), None, None),
    ("SAM_UEI", "gov_cui", re.compile(r"(?:UEI|Unique\s+Entity\s+(?:Identifier|ID)?)\s*[:#-]?\s*[A-Z0-9]{12}\b", re.I), None, None),
    ("DIST_STMT", "gov_cui", re.compile(r"\bDistribution\s+Statement\s+[A-F]\b\.?", re.I), None, None),
    ("FOUO", "gov_cui", re.compile(r"\bFOUO\b|\bFOR\s+OFFICIAL\s+USE\s+ONLY\b", re.I), None, None),
    ("DIST_CTRL", "gov_cui", re.compile(r"\b(?:NOFORN|LIMDIS|ORCON|PROPIN)\b", re.I), None, None),
    ("REL_TO", "gov_cui", re.compile(r"\bREL\s+TO\s+[A-Z]{2,5}(?:[,\s]+[A-Z]{2,5})*\b"), None, None),
    ("EXPORT_CTRL", "gov_cui", re.compile(
        r"\b(?:ITAR|EAR[\s-]?99|EAR\s+Controlled|Export\s+Controlled(?:\s+Item)?)\b", re.I), None, None),
    ("ECCN", "gov_cui", re.compile(r"\bECCN\s+[0-9][A-Z][0-9]{3}[a-z]?\b", re.I), None, None),
    ("GOV_EMAIL", "gov_cui", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(?:gov|mil)\b", re.I), None, None),
    ("FEDRAMP_ID", "gov_cui", re.compile(
        r"(?:FedRAMP(?:\s+(?:Authorization|P-ATO|ATO|Package\s+ID|ID))?)\s*[:#-]?\s*F[0-9]{7,10}\b", re.I), None, None),
    ("FEDRAMP_ID", "gov_cui", re.compile(r"\bFR\d{8,11}\b"), None, None),
]


def _emit_label(type_id: str) -> str:
    """Map internal pattern type-id to the placeholder label emitted.
    CRYPTO_KEY_64HEX exists only for the basic/non-basic gate."""
    return "CRYPTO_KEY" if type_id == "CRYPTO_KEY_64HEX" else type_id


# ---------------------------------------------------------------------------
# Input normalisation (dlp.js FIX 1): NFKC + zero-width strip, with an offset
# map back to original positions. Detection runs on `norm`; redaction targets
# the ORIGINAL text via the map, so non-secret text is never silently altered.
# ---------------------------------------------------------------------------
_ZERO_WIDTH = {"​", "‌", "‍", "﻿", "⁠"}


def _normalize_with_map(s: str) -> tuple[str, list[int]]:
    norm_chars: list[str] = []
    to_orig: list[int] = []
    for i, ch in enumerate(s):
        if ch in _ZERO_WIDTH:
            continue
        if ch == " ":      # NBSP -> ASCII space
            ch = " "
        elif ch == "‑":    # non-breaking hyphen -> hyphen
            ch = "-"
        nfkc = unicodedata.normalize("NFKC", ch)
        for c in nfkc:
            norm_chars.append(c)
            to_orig.append(i)
    return "".join(norm_chars), to_orig


# ---------------------------------------------------------------------------
# Exfiltration Shield — threshold-based bulk-copy detector. Mirrors dlp.js
# _checkExfiltration. Returns a block dict when triggered, else None.
# ---------------------------------------------------------------------------
_EXFIL_SSN_THRESHOLD = 3
_EXFIL_CC_THRESHOLD = 5
_EXFIL_EMAIL_THRESHOLD = 20

_RE_EXFIL_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_RE_EXFIL_CC = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{3,4}\b")
_RE_EXFIL_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def check_exfiltration(text: str, shields: Optional[dict] = None) -> Optional[dict]:
    """Return a bulk-exfiltration block dict, or None if clear.
    Never logs or persists `text`."""
    if shields is not None and shields.get("exfiltrationShield") is False:
        return None

    ssn = _RE_EXFIL_SSN.findall(text)
    if len(ssn) >= _EXFIL_SSN_THRESHOLD:
        return {"blocked": True, "errorCode": "BULK_EXFILTRATION_RISK",
                "matchCount": len(ssn), "categories": ["bulk_ssn"]}

    raw_cc = _RE_EXFIL_CC.findall(text)
    # findall on this regex returns the last repeating group; re-match to get
    # full strings, then Luhn-filter to match Desktop behaviour.
    valid_cc = [m.group(0) for m in _RE_EXFIL_CC.finditer(text) if _v_credit_card(m.group(0))]
    if len(valid_cc) >= _EXFIL_CC_THRESHOLD:
        return {"blocked": True, "errorCode": "BULK_EXFILTRATION_RISK",
                "matchCount": len(valid_cc), "categories": ["bulk_credit_card"]}

    emails = _RE_EXFIL_EMAIL.findall(text)
    if len(emails) >= _EXFIL_EMAIL_THRESHOLD:
        return {"blocked": True, "errorCode": "BULK_EXFILTRATION_RISK",
                "matchCount": len(emails), "categories": ["bulk_email"]}

    return None


# ---------------------------------------------------------------------------
# Shield gate — mirrors dlp.js _patternEnabled.
# ---------------------------------------------------------------------------
def _pattern_enabled(type_id: str, group: str, shields: dict) -> bool:
    if group == "devsec":
        if type_id in _DEVSEC_NON_BASIC:
            return shields.get("devsec") is not False
        return shields.get("basicProtection") is not False
    if group == "customTerms":
        return shields.get("customTerms") is True
    return shields.get(group) is not False


# ---------------------------------------------------------------------------
# Core redaction engine — faithful port of dlp.js protectRelayText.
#   - Exfiltration runs FIRST (returns a block dict).
#   - NFKC + zero-width normalisation with offset map; detect on norm,
#     redact the ORIGINAL via the map.
#   - Definition-order precedence with claimed-span suppression (earlier wins).
#   - Left-to-right numbering per type ([TYPE_1], [TYPE_2], ...).
#   - Right-to-left application.
#   - FAIL-CLOSED: any engine error returns a block dict.
# ---------------------------------------------------------------------------
def protect_relay_text(text: str, shields: Optional[dict] = None, *,
                       emoji: bool = False,
                       vault: Optional[dict] = None,
                       custom_terms: Optional[list[str]] = None) -> dict:
    """Protect `text`. Returns one of:
        {"text": str, "redacted": [{"type","count"}], "wasModified": bool}
        {"blocked": True, "errorCode": str, "matchCount": int, "categories": [str]}

    `emoji`      prefixes placeholders with 🔒.
    `vault`      if provided, each redacted span's original value is stored
                 under its placeholder (CLI reversible vault / NDA).
    `custom_terms` optional list of verbatim strings to redact as CUSTOM_TERM
                 (word-boundary, case-insensitive) — only when shields.customTerms.
    """
    if not isinstance(text, str) or not text:
        return {"text": text or "", "redacted": [], "wasModified": False}
    if not isinstance(shields, dict):
        shields = {}

    prefix = "🔒" if emoji else ""

    try:
        # 1. Exfiltration Shield — blocks before any redaction.
        exfil = check_exfiltration(text, shields)
        if exfil:
            return exfil

        # 2. Normalised detection target + offset map.
        norm, to_orig = _normalize_with_map(text)

        # 3. Build the active pattern list (built-ins + custom terms).
        active: list = []
        for entry in _PATTERNS:
            type_id, group, pattern, validator, strategy = entry
            if _pattern_enabled(type_id, group, shields):
                active.append(entry)

        if shields.get("customTerms") is True and custom_terms:
            # FAIL-CLOSED on custom-term compile error (matches dlp.js contract).
            try:
                for term in custom_terms:
                    if not term or not isinstance(term, str) or not term.strip():
                        continue
                    escaped = re.escape(term.strip())
                    cre = re.compile(r"(?<![\w-])" + escaped + r"(?![\w-])", re.IGNORECASE)
                    active.append(("CUSTOM_TERM", "customTerms", cre, None, None))
            except re.error:
                return {"blocked": True, "errorCode": "PROTECTION_ENGINE_ERROR",
                        "matchCount": 0, "categories": []}

        # 4. Collect spans with definition-order precedence + claimed-span
        #    suppression. claimed = list of (orig_start, orig_end) already taken.
        type_counts: dict[str, int] = {}
        all_spans: list[dict] = []
        claimed: list[tuple[int, int]] = []

        for type_id, group, pattern, validator, strategy in active:
            emit = _emit_label(type_id)
            pat_matches: list[dict] = []

            for m in pattern.finditer(norm):
                if m.group(0) == "":
                    continue

                # Determine the redacted sub-span (norm coords). For the
                # label-preserving strategies the span is ONLY group(2) (the
                # value); group(1)/group(3) stay in the original text outside
                # the span, so the replacement is just the token. This mirrors
                # dlp.js, where the lookbehind/lookahead keeps the label out of
                # m[0] and leaves @host free for a later pattern (e.g. IP).
                if strategy in ("preserve_conn", "preserve_group1"):
                    val = m.group(2)
                    if strategy == "preserve_group1" and validator and not validator(val):
                        continue
                    norm_start = m.start(2)
                    norm_end = m.end(2)
                    val_for_vault = val
                else:
                    val = m.group(0)
                    if validator and not validator(val):
                        continue
                    if callable(strategy) and not strategy(m, norm):
                        continue
                    norm_start = m.start(0)
                    norm_end = m.end(0)
                    val_for_vault = val

                # Map normalised span -> original span.
                orig_start = to_orig[norm_start]
                orig_end = to_orig[norm_end - 1] + 1

                # Claimed-span suppression (earlier/higher-priority wins).
                if any(orig_start < ce and orig_end > cs for cs, ce in claimed):
                    continue

                pat_matches.append({"orig_start": orig_start, "orig_end": orig_end,
                                    "val": val_for_vault})

            # Number this pattern's matches left-to-right.
            pat_matches.sort(key=lambda d: d["orig_start"])
            for pm in pat_matches:
                n = type_counts.get(emit, 0) + 1
                type_counts[emit] = n
                replacement = f"{prefix}[{emit}_{n}]"
                if vault is not None:
                    vault[f"[{emit}_{n}]"] = pm["val"]
                all_spans.append({"orig_start": pm["orig_start"],
                                  "orig_end": pm["orig_end"],
                                  "replacement": replacement})
                claimed.append((pm["orig_start"], pm["orig_end"]))

        # 5. Apply replacements right-to-left (preserves earlier positions).
        all_spans.sort(key=lambda d: d["orig_start"], reverse=True)
        result = text
        for span in all_spans:
            result = result[:span["orig_start"]] + span["replacement"] + result[span["orig_end"]:]

        redacted = [{"type": t, "count": c} for t, c in type_counts.items()]
        return {"text": result, "redacted": redacted, "wasModified": len(redacted) > 0}

    except Exception:
        # FAIL-CLOSED: never emit raw text on an engine error.
        return {"blocked": True, "errorCode": "PROTECTION_ENGINE_ERROR",
                "matchCount": 0, "categories": []}


class SafeRelayClient:
    """
    Local, zero-trust DLP client for Python (CI/CD, serverless, CLI).

    Modes:
        zero-trust  — redacts in place, nothing leaves the process (default)
        audit       — redacts and records detections for logging/reporting

    Mirrors the canonical eight-shield engine. By default all portable shields
    are active (basicProtection, devsec, fintech, corporate, civic, gov_cui,
    exfiltrationShield). Pass a `shields` dict to toggle.
    """

    #: default shield state — every portable shield on (customTerms is
    #: browser/CLI-local and defaults off).
    DEFAULT_SHIELDS = {
        "basicProtection": True,
        "devsec": True,
        "fintech": True,
        "corporate": True,
        "civic": True,
        "gov_cui": True,
        "exfiltrationShield": True,
        "customTerms": False,
    }

    def __init__(self, mode: Literal["zero-trust", "audit"] = "zero-trust",
                 shields: Optional[dict] = None):
        self.mode = mode
        self.shields = dict(self.DEFAULT_SHIELDS)
        if shields:
            self.shields.update(shields)
        self._detections: dict[str, int] = {}
        self._last_block: Optional[dict] = None

    def redact(self, text: str, emoji: bool = True) -> str:
        """Redact all detected secrets and PII from *text*.

        If the Exfiltration Shield fires (bulk SSN/CC/email), raises
        SafeRelayBlocked — matching the browser/desktop hard-block contract.
        On any engine error the relay also blocks (fail-closed).
        """
        if not text:
            self._detections = {}
            self._last_block = None
            return text

        result = protect_relay_text(text, self.shields, emoji=emoji)
        if result.get("blocked"):
            self._detections = {}
            self._last_block = result
            raise SafeRelayBlocked(result)

        self._last_block = None
        self._detections = {d["type"]: d["count"] for d in result["redacted"]}
        return result["text"]

    def is_safe(self, text: str) -> bool:
        """Return True if no secrets are detected (and no bulk block fires)."""
        if not text:
            return True
        result = protect_relay_text(text, self.shields, emoji=False)
        if result.get("blocked"):
            return False
        return result["text"] == text

    @property
    def last_detections(self) -> dict[str, int]:
        """Dict of {PATTERN_TYPE: count} from the last redact() call."""
        return dict(self._detections)

    @property
    def last_detection_count(self) -> int:
        """Total number of secrets found in the last redact() call."""
        return sum(self._detections.values())

    @property
    def last_block(self) -> Optional[dict]:
        """The block dict from the last redact() call, or None."""
        return self._last_block


class SafeRelayBlocked(Exception):
    """Raised when the Exfiltration Shield (or a fail-closed engine error)
    blocks a relay. Carries the structured block dict."""

    def __init__(self, block: dict):
        self.block = block
        cats = ", ".join(block.get("categories", [])) or block.get("errorCode", "blocked")
        super().__init__(
            f"SafeRelay blocked relay: {block.get('errorCode')} "
            f"(matchCount={block.get('matchCount')}, categories={cats})"
        )


# Introspection helpers (mirror SDK exports). Placeholder labels (not internal
# type-ids), de-duplicated and sorted.
PATTERN_TYPES = sorted({_emit_label(p[0]) for p in _PATTERNS})

# Shield groups present in the registry (for CLI/status introspection).
PATTERN_GROUPS = sorted({p[1] for p in _PATTERNS})
