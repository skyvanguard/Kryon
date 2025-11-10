---
description: "Get creative hints without spoiling the challenge"
---

# CTF Hint System

When you need a nudge in the right direction without full spoilers.

## Hint Generation Strategy

### Level 1: Generic Hints (No Spoilers)
Ask yourself:
- What services are exposed?
- Have I enumerated EVERYTHING?
- Did I check for hidden files/directories?
- Have I tested ALL input fields?
- Am I thinking too complicated?

### Level 2: Direction Hints
Based on what you've found, consider:
- **If you found a web app**: Focus on common web vulns (SQLi, XSS, LFI, RCE)
- **If you found SSH**: Look for credentials (files, databases, default)
- **If you found SMB**: Enumerate shares, check for null sessions
- **If you found unusual service**: Web search it! Research is key.

### Level 3: Technique Hints
Search for these techniques related to your findings:
```
# For each service found, search:
"[service_name] [version] ctf technique"
"[service_name] common vulnerabilities"
"[service_name] default configuration exploit"
```

### Level 4: Similar Challenges
Search for similar machines:
```
"tryhackme similar to [challenge_name]"
"hackthebox [service_name] writeup"
"ctf [main_technology] challenge writeup"
```

### Level 5: Nudge (Light Spoiler)
If really stuck, search:
```
"[challenge_name] hint"
"[challenge_name] forum discussion"
```

Read only the FIRST hint - see if that's enough.

## Creative Thinking Prompts

When completely stuck, think about:

### "What if...?"
- What if the vulnerability is in an unexpected place?
- What if I need to combine multiple small issues?
- What if the answer is simpler than I think?
- What if there's steganography or hidden data?

### "Have I tried...?"
- Default credentials (admin/admin, root/root, guest/guest)
- Common passwords (password, Password123!, admin, etc.)
- SQL injection in EVERY input field
- Directory fuzzing with multiple wordlists
- Checking ALL HTTP methods (GET, POST, PUT, DELETE, OPTIONS)
- Parameter tampering (changing IDs, adding debug=true, etc.)

### "Did I check...?"
- robots.txt, sitemap.xml
- .git directory, .env file, backup files
- Source code comments
- Hidden form fields
- Cookie values
- HTTP headers
- URL parameters
- Error messages (they leak info!)

## Anti-Rabbit-Hole Checklist

Before going deep down a path, verify:
- ✅ Is this based on actual findings or assumptions?
- ✅ Have I verified this is exploitable?
- ✅ Am I spending too much time on low-priority items?
- ✅ Should I try something else first?

## The "Take a Break" Protocol

If stuck for >30 minutes:
1. Take a 5-minute break
2. Come back and describe the challenge out loud
3. List EVERYTHING you know
4. List EVERYTHING you've tried
5. Search for writeups of similar challenges
6. Try ONE thing you haven't tried yet

## Web Research for Hints

Smart searches that don't spoil too much:
```
# Good (learns approach)
"[challenge_type] methodology"
"[technology] enumeration techniques"
"[service] common misconfigurations"

# Acceptable (learns pattern)
"tryhackme [category] beginner writeup"
"how to approach [challenge_type] ctf"

# Last resort (partial spoiler)
"[exact_challenge_name] first hint"
"[exact_challenge_name] forum help"
```

## Hint Request Format

When asking for a hint, provide:
1. **Target info**: What you know about the system
2. **What you've tried**: Enumeration results, exploits attempted
3. **Where you're stuck**: Specific blocker
4. **What you need**: Type of hint (direction, technique, nudge)

Example:
```
Target: TryHackMe "BasicPentesting" box
Found: Apache 2.4.29, SSH on 22, port 8080 with web app
Tried: Directory fuzzing, SQL injection on login, default creds
Stuck: Can't find entry point to web app
Need: Direction hint - what web vulnerabilities should I focus on?
```

## Output

Provides:
- Contextual hints based on your progress
- Web search results for similar challenges
- Technique suggestions without full spoilers
- Questions to ask yourself
- Alternative approaches to try

**Usage**: `/ctf-hint [describe what you've tried]`
