"""
Oubliette Shield - Input Sanitizer
Sanitizes user input to prevent markup-based injection attacks.

Targets:
- HTML/XML tag injection (ATK-031)
- Markdown injection (ATK-032)
- CSV formula injection (ATK-033)
"""

import re
import html


def sanitize_input(user_input):
    """
    Sanitize user input to prevent markup-based injection attacks.

    Returns:
        tuple: (sanitized_text, list_of_applied_sanitizations)
    """
    sanitizations_applied = []

    # 1. HTML/XML Tag Stripping
    html_tag_pattern = r'<[^>]+>'
    if re.search(html_tag_pattern, user_input):
        user_input = re.sub(html_tag_pattern, '', user_input)
        sanitizations_applied.append("html_tags_removed")

    # 2. HTML Entity Decoding (prevent double-encoding attacks)
    decoded_input = html.unescape(user_input)
    if decoded_input != user_input:
        user_input = decoded_input
        sanitizations_applied.append("html_entities_decoded")

    # 3. Markdown Link Injection Prevention
    markdown_link_pattern = r'\[([^\]]+)\]\([^\)]+\)'
    if re.search(markdown_link_pattern, user_input):
        user_input = re.sub(markdown_link_pattern, r'\1', user_input)
        sanitizations_applied.append("markdown_links_removed")

    # 4. Markdown Image Injection Prevention
    markdown_img_pattern = r'!\[([^\]]*)\]\([^\)]+\)'
    if re.search(markdown_img_pattern, user_input):
        user_input = re.sub(markdown_img_pattern, r'\1', user_input)
        sanitizations_applied.append("markdown_images_removed")

    # 5. CSV Formula Injection Prevention
    csv_formula_indicators = ['=', '+', '-', '@']
    if any(user_input.strip().startswith(char) for char in csv_formula_indicators):
        user_input = user_input.lstrip(''.join(csv_formula_indicators))
        sanitizations_applied.append("csv_formula_prefix_removed")

    # 6. Script Tag Removal (additional protection)
    script_pattern = r'<script[^>]*>.*?</script>'
    if re.search(script_pattern, user_input, re.IGNORECASE | re.DOTALL):
        user_input = re.sub(script_pattern, '', user_input, flags=re.IGNORECASE | re.DOTALL)
        sanitizations_applied.append("script_tags_removed")

    # 7. Inline Event Handler Removal (onclick, onerror, etc.)
    event_handler_pattern = r'\bon\w+\s*=\s*["\'][^"\']*["\']'
    if re.search(event_handler_pattern, user_input, re.IGNORECASE):
        user_input = re.sub(event_handler_pattern, '', user_input, flags=re.IGNORECASE)
        sanitizations_applied.append("event_handlers_removed")

    # 8. XML CDATA Section Removal
    cdata_pattern = r'<!\[CDATA\[.*?\]\]>'
    if re.search(cdata_pattern, user_input, re.DOTALL):
        user_input = re.sub(cdata_pattern, '', user_input, flags=re.DOTALL)
        sanitizations_applied.append("cdata_sections_removed")

    # 9. Normalize whitespace (prevent whitespace obfuscation)
    normalized_input = ' '.join(user_input.split())
    if normalized_input != user_input:
        user_input = normalized_input
        sanitizations_applied.append("whitespace_normalized")

    if sanitizations_applied:
        print(f"[SHIELD-SANITIZER] Applied: {', '.join(sanitizations_applied)}")

    return user_input, sanitizations_applied
