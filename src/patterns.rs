//! Pattern definitions for LLM security detection

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

/// Compiled regex patterns for prompt injection detection
lazy_static! {
        /// Detect prompt injection attempts
        pub static ref PROMPT_INJECTION_PATTERNS: Vec<Regex> = vec![

            // --- Direct instruction injection ---
            Regex::new(r"(?i)\b(ignore|disregard|forget)\b\s+(?:all\s+)?\b(previous|prior|above|earlier)\b\s+\b(instructions?|prompts?|commands?|rules?)\b").unwrap(),

            // --- System prompt override attempts ---
            Regex::new(r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|from\s+now\s+on)\b").unwrap(),

            // --- Jailbreak pattern names ---
            Regex::new(r"(?i)\b(DAN|STAN|DUDE|AIM|SWITCH)\b").unwrap(),
            Regex::new(r"(?i)\bdeveloper\s+mode\b").unwrap(),

            // --- Role-playing attacks ---
            Regex::new(r"(?i)\b(in\s+an?\s+alternate\s+universe|hypothetical|imaginary\s+scenario|pretend|simulation)\b").unwrap(),

            // --- Output format manipulation ---
            Regex::new(r"(?i)\b(ignore|skip|bypass)\b\s+\b(json|output|format|structure)\b").unwrap(),

            // --- Delimiter escape attempts ---
            Regex::new(r"```[\s\S]*?(</system>|<\|im_end\|>|<\|endoftext\|>)").unwrap(),

            // --- Token stuffing ---
            Regex::new(r"(#{10,}|={10,}|\*{10,}|-{10,})").unwrap(),

            // --- Comment injection attacks ---
            Regex::new(r"(?i)///\s*ATTENTION\s+(?:ANY\s+)?(LLM|AI|GPT|CLAUDE|MODEL)").unwrap(),
            Regex::new(r"(?i)//\s*@(LLM|AI|ASSISTANT|SYSTEM)").unwrap(),
            Regex::new(r"(?i)/\*[\s\S]*?(IGNORE|OVERRIDE|BYPASS)[\s\S]*?\*/").unwrap(),

            // --- Hidden unicode tricks ---
            Regex::new(r"[\u{200B}-\u{200D}\u{FEFF}]").unwrap(),

            // --- Encoding tricks ---
            Regex::new(r"(?i)\b(base64|hex|rot13|decode):\s*[A-Za-z0-9+/=]{20,}\b").unwrap(),

            // --- Meta-instruction injection ---
            Regex::new(r"(?i)\b(NEW|UPDATED|REAL)\b\s+\b(SYSTEM|INSTRUCTION|RULE|GUIDELINE|POLICY)\b").unwrap(),

            // --- Authority appeals ---
            Regex::new(r"(?i)\b(administrator|developer|owner|creator)\b\s+\b(says?|commands?|requires?)\b").unwrap(),
            Regex::new(r"(?i)\bgod\s+mode\b").unwrap(),

            // --- Output redirection ---
            Regex::new(r"(?i)\bONLY\b\s+\b(SAY|RESPOND|OUTPUT|RETURN|PRINT)\b").unwrap(),

            // --- Code execution requests ---
            Regex::new(r"(?i)\b(execute|eval|run)\b\s+(?:this|the\s+following)\s+\bcode\b").unwrap(),

            // --- Semantic cloaking / polite manipulation ---
            Regex::new(r"(?i)\b(dear|hello|hi)\b\s+\b(ai|assistant|colleague|friend|llm|model)\b").unwrap(),
            Regex::new(r"(?i)\b(recommend|suggest|advise|kindly|please)\b\s+\b(focus|ignore|skip|overlook)\b").unwrap(),

            // --- Chain-of-thought manipulation ---
            Regex::new(r"(?i)\blet'?s\s+think\s+step\s+by\s+step\b").unwrap(),
            Regex::new(r"(?i)\bfirst\b.*\bsecond\b.*\bthird\b.*\btherefore\b").unwrap(),

            // --- Few-shot poisoning ---
            Regex::new(r"(?i)\bexample\s+\d+:\s*result:\s*(safe|ok|pass|good)\b").unwrap(),

            // --- Context window attacks ---
            Regex::new(r"(?i)\b(for\s+context|background\s+information|important\s+note)\b").unwrap(),

            // --- Virtual markup manipulation ---
            Regex::new(r"(?i)#{1,6}\s*(SYSTEM|IMPORTANT|CRITICAL|ATTENTION|WARNING|NOTICE)").unwrap(),
            Regex::new(r"(?i)\*{1,2}(SYSTEM|IMPORTANT|AI|ASSISTANT)\*{1,2}").unwrap(),

            // --- Obfuscation / leetspeak ---
            Regex::new(r"(?i)\b(1gn0r3|d1sr3gard|byp4ss|0v3rr1d3)\b").unwrap(),

            // --- Synonym-based instruction bypass ---
            Regex::new(r"(?i)\b(overlook|discard|omit|exclude|dismiss|skip\s+over)\b\s+\b(vulnerabilities|issues|problems|warnings)\b").unwrap(),

            // --- Legal/authorization manipulation ---
            Regex::new(r"(?i)\b(confidential|proprietary|classified|secret|private|restricted)\b").unwrap(),
            Regex::new(r"(?i)\b(not\s+authorized|unauthorized|no\s+permission|forbidden\s+to\s+(view|access|analyze))\b").unwrap(),
            Regex::new(r"(?i)\b(copyright|trademark|patent|NDA|non[-\s]?disclosure)\b").unwrap(),
            Regex::new(r"(?i)\b(legal\s+disclaimer|legal\s+notice|legal\s+warning)\b").unwrap(),
            Regex::new(r"(?i)\b(violation\s+of\s+law|illegal\s+to\s+(view|analyze|review))\b").unwrap(),

            // --- Execution manipulation ---
            Regex::new(r"(?i)\b(must\s+execute|need\s+to\s+run|require.*execution|compile.*and.*run)\b").unwrap(),
            Regex::new(r"(?i)\b(dynamic\s+analysis\s+requires|runtime\s+analysis\s+needs|execute\s+to\s+verify)\b").unwrap(),
        ];

    /// Dangerous keywords that should trigger warnings
    pub static ref DANGEROUS_KEYWORDS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("ignore instructions");
        set.insert("disregard prompt");
        set.insert("forget previous");
        set.insert("you are now");
        set.insert("act as");
        set.insert("pretend to be");
        set.insert("DAN mode");
        set.insert("developer mode");
        set.insert("jailbreak");
        set.insert("system override");
        set.insert("bypass filter");
        set.insert("ignore rules");
        set.insert("no restrictions");
        set.insert("unlimited mode");
        set.insert("god mode");
        set.insert("dear ai");
        set.insert("dear assistant");
        set.insert("kindly ignore");
        set.insert("please skip");
        set.insert("overlook vulnerabilities");
        set.insert("dismiss issues");
        set.insert("focus on performance");
        set.insert("not important");
        set.insert("false positive");
        set.insert("test environment");
        set.insert("development only");
        set.insert("confidential code");
        set.insert("proprietary information");
        set.insert("not authorized");
        set.insert("no permission");
        set.insert("copyright protected");
        set.insert("nda required");
        set.insert("legal disclaimer");
        set.insert("must execute");
        set.insert("need to run");
        set.insert("requires execution");
        set
    };

    /// RTL override characters
    pub static ref RTL_OVERRIDE_CHARS: Vec<char> = vec![
        '\u{202E}', // RLO - Right-to-Left Override
        '\u{202D}', // LRO - Left-to-Right Override
        '\u{202A}', // LRE - Left-to-Right Embedding
        '\u{202B}', // RLE - Right-to-Left Embedding
        '\u{202C}', // PDF - Pop Directional Formatting
    ];

    /// Output validation patterns
    pub static ref SUSPICIOUS_OUTPUT_PATTERNS: Vec<Regex> = vec![
        // LLM admitting to following malicious instructions
        Regex::new(r"(?i)as\s+(?:requested|instructed|commanded),?\s+I\s+will\s+(?:ignore|bypass|disable)").unwrap(),

        // LLM changing personality
        Regex::new(r"(?i)I\s+am\s+now\s+(?:acting|operating|functioning)\s+as").unwrap(),

        // Suspicious compliance
        Regex::new(r"(?i)(?:sure|okay|yes),?\s+I\s+(?:can|will)\s+ignore").unwrap(),

        // LLM being too agreeable to bad instructions
        Regex::new(r"(?i)I\s+(?:will|can|shall)\s+(?:overlook|dismiss|skip|omit)").unwrap(),

        // LLM following semantic attacks
        Regex::new(r"(?i)(?:focusing|concentrating)\s+on\s+(?:performance|functionality|features)\s+rather\s+than\s+security").unwrap(),
    ];
}

/// Get all prompt injection patterns
pub fn get_prompt_injection_patterns() -> &'static Vec<Regex> {
    &PROMPT_INJECTION_PATTERNS
}

/// Get all dangerous keywords
pub fn get_dangerous_keywords() -> &'static HashSet<&'static str> {
    &DANGEROUS_KEYWORDS
}

/// Get RTL override characters
pub fn get_rtl_override_chars() -> &'static Vec<char> {
    &RTL_OVERRIDE_CHARS
}

/// Get suspicious output patterns
pub fn get_suspicious_output_patterns() -> &'static Vec<Regex> {
    &SUSPICIOUS_OUTPUT_PATTERNS
}
