with open("templates/base.html", "r", encoding="utf-8") as f:
    content = f.read()

marker = "Case Management"
idx = content.find(marker)
if idx == -1:
    print("Marker not found!")
else:
    # find the end of this <li>...</li> block (next "</li>" after marker)
    end_li = content.find("</li>", idx)
    end_li += len("</li>")
    insert = """
                            <li>
                                <a class="dropdown-item {% if request.url.path == '/tickets' %}active{% endif %}" href="/tickets">
                                    <i class="bi bi-ticket-perforated"></i> Incident Tickets
                                </a>
                            </li>"""
    new_content = content[:end_li] + insert + content[end_li:]
    with open("templates/base.html", "w", encoding="utf-8") as f:
        f.write(new_content)
    print("Inserted successfully after position", end_li)
