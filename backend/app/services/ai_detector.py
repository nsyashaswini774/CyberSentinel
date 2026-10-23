import re
from typing import Dict, List, Tuple, Any

# Lexical intent pattern banks for Phishing & Social Engineering Detection
INTENT_PATTERNS: Dict[str, List[str]] = {
    "Credential Harvesting": [
        r"verify (?:your )?(?:[a-zA-Z0-9_-]+ )?(?:password|account|identity|credentials)",
        r"update (?:your )?(?:[a-zA-Z0-9_-]+ )?(?:login|credentials|password|profile)",
        r"unusual (?:sign-in|activity|login)",
        r"re-authenticate",
        r"confirm (?:your )?(?:identity|email|details)",
        r"click (?:the )?(?:secure )?link",
        r"reset (?:your )?password",
        r"security (?:alert|notice|warning)",
        r"account (?:suspended|locked|flagged|restricted|disabled)",
        r"login credentials",
    ],
    "Urgent Coercion": [
        r"immediately",
        r"within 24 hours",
        r"urgent (?:action|notice|attention)",
        r"mandatory",
        r"immediate (?:response|action|verification|attention)",
        r"final (?:notice|warning)",
        r"failure to (?:respond|verify|comply)",
        r"permanent (?:account )?suspension",
        r"act fast",
        r"time sensitive",
    ],
    "Business Email Compromise (BEC) & Financial": [
        r"wire transfer",
        r"payment overdue",
        r"overdue invoice",
        r"direct deposit",
        r"payroll (?:update|deposit|form)",
        r"invoice attached",
        r"gift card",
        r"remittance",
        r"routing number",
        r"settlement required",
        r"bonus distribution",
    ],
    "Authority Impersonation": [
        r"it support(?: helpdesk)?",
        r"security operations(?: center)?",
        r"system administrator",
        r"hr department",
        r"corporate it",
        r"office of the ceo",
        r"compliance team",
        r"executive board",
    ],
}


def analyze_email_intent(subject: str, body_text: str) -> Dict[str, Any]:
    """
    NLP and pattern-based email intent analyzer.
    Identifies social engineering tactics, urgency coercion, credential harvesting,
    and calculates AI confidence score and explainability indicators.
    """
    combined_text = f"{subject}\n{body_text}".lower()
    
    detected_triggers: Dict[str, List[str]] = {}
    total_matches = 0
    all_flagged_phrases: List[str] = []

    for category, patterns in INTENT_PATTERNS.items():
        matched_in_category = []
        for pattern in patterns:
            found = re.findall(pattern, combined_text)
            if found:
                matched_in_category.extend(found)
                for item in found:
                    phrase = item.strip()
                    if phrase not in all_flagged_phrases:
                        all_flagged_phrases.append(phrase)
        if matched_in_category:
            detected_triggers[category] = list(set(matched_in_category))
            total_matches += len(detected_triggers[category])

    # Check for visual manipulation indicators (Excessive caps, urgency punctuation)
    caps_words = re.findall(r'\b[A-Z]{4,}\b', f"{subject} {body_text}")
    excessive_urgency_caps = [w for w in caps_words if w in {"URGENT", "IMMEDIATELY", "MANDATORY", "CRITICAL", "ACTION", "WARNING", "ALERT"}]
    if excessive_urgency_caps:
        for w in excessive_urgency_caps:
            if w not in all_flagged_phrases:
                all_flagged_phrases.append(w)

    # Determine predominant intent category
    if "Credential Harvesting" in detected_triggers:
        intent_category = "Credential Harvesting"
    elif "Business Email Compromise (BEC) & Financial" in detected_triggers:
        intent_category = "Business Email Compromise (BEC)"
    elif "Urgent Coercion" in detected_triggers:
        intent_category = "Urgent Coercion"
    elif "Authority Impersonation" in detected_triggers:
        intent_category = "Authority Impersonation"
    else:
        intent_category = "Benign / Normal Communication"

    # Compute AI Confidence score (0.0 to 1.0)
    if total_matches == 0:
        ai_confidence = 0.05
        ai_score = 0.0
    elif total_matches == 1:
        ai_confidence = 0.45
        ai_score = 8.0
    elif total_matches == 2:
        ai_confidence = 0.75
        ai_score = 16.0
    elif total_matches >= 3:
        ai_confidence = min(0.98, 0.85 + (total_matches * 0.03))
        ai_score = 25.0
    else:
        ai_confidence = 0.5
        ai_score = 10.0

    # Boost confidence if authority impersonation + credential harvesting/BEC are combined (hallmark spear-phishing)
    if ("Authority Impersonation" in detected_triggers and 
        ("Credential Harvesting" in detected_triggers or "Business Email Compromise (BEC)" in detected_triggers)):
        ai_confidence = min(0.99, ai_confidence + 0.1)
        ai_score = min(25.0, ai_score + 5.0)

    # Generate explanatory rationale
    explanation_parts = []
    if "Credential Harvesting" in detected_triggers:
        explanation_parts.append(f"Contains credential acquisition lures ({', '.join(detected_triggers['Credential Harvesting'][:2])})")
    if "Urgent Coercion" in detected_triggers:
        explanation_parts.append(f"Uses artificial time pressure and threats ({', '.join(detected_triggers['Urgent Coercion'][:2])})")
    if "Business Email Compromise (BEC) & Financial" in detected_triggers:
        explanation_parts.append(f"Targets financial transactions or sensitive payroll credentials ({', '.join(detected_triggers['Business Email Compromise (BEC) & Financial'][:2])})")
    if "Authority Impersonation" in detected_triggers:
        explanation_parts.append(f"Impersonates internal corporate hierarchy ({', '.join(detected_triggers['Authority Impersonation'][:2])})")

    ai_explanation = "; ".join(explanation_parts) if explanation_parts else "Language patterns consistent with standard benign communication."

    return {
        "intent_category": intent_category,
        "ai_confidence": round(ai_confidence, 2),
        "ai_content_score": round(ai_score, 1),
        "flagged_phrases": all_flagged_phrases[:8],
        "detected_triggers": detected_triggers,
        "ai_explanation": ai_explanation,
    }
