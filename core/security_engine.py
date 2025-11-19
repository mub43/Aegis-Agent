"""
AEGIS AGENT - Real-Time AI Threat Mitigation Security Engine

This module implements a sophisticated threat-scoring system using weighted-regex
heuristics to detect prompt injection and jailbreak attempts in LLM interactions.
"""

import re
import time
from typing import Tuple, Dict, List
from enum import Enum


class MitigationAction(str, Enum):
    """Enumeration of possible mitigation actions."""
    BLOCK = "BLOCK"
    FLAG = "FLAG"
    PASS = "PASS"


class SecurityEngine:
    """
    Core security engine for real-time threat detection and mitigation.
    
    Uses weighted-regex patterns to simulate a sophisticated LangChain/LLM classifier
    for detecting prompt injection and jailbreak attempts.
    """
    
    def __init__(self):
        """Initialize the security engine with threat detection patterns."""
        # High-severity patterns (weight: 1.0) - Direct injection attempts
        self._high_severity_patterns: List[Tuple[str, float]] = [
            (r'ignore\s+(previous|all|above|prior)\s+(instructions|prompts|commands)', 1.0),
            (r'forget\s+(everything|all|previous)', 1.0),
            (r'you\s+are\s+now\s+(a|an)\s+', 1.0),
            (r'act\s+as\s+if\s+you\s+are', 1.0),
            (r'system\s*:\s*', 1.0),
            (r'<\|(system|assistant|user)\|>', 1.0),
            (r'\[INST\]', 1.0),
            (r'roleplay|role\s+play', 1.0),
            (r'jailbreak|jail\s+break', 1.0),
            (r'bypass\s+(security|safety|filters)', 1.0),
            (r'override\s+(system|safety|security)', 1.0),
            (r'pretend\s+you\s+are', 1.0),
            (r'disregard\s+(all|previous|above)', 1.0),
        ]
        
        # Medium-severity patterns (weight: 0.7) - Suspicious behavior
        self._medium_severity_patterns: List[Tuple[str, float]] = [
            (r'hidden\s+(instructions|prompts|commands)', 0.7),
            (r'secret\s+(instructions|prompts|commands)', 0.7),
            (r'inner\s+(thoughts|monologue|dialogue)', 0.7),
            (r'think\s+(step\s+by\s+step|carefully|out\s+loud)', 0.7),
            (r'decode|decrypt|unscramble', 0.7),
            (r'base64|hex|binary', 0.7),
            (r'execute\s+(code|command|script)', 0.7),
            (r'run\s+(code|command|script)', 0.7),
            (r'evade|circumvent|avoid\s+detection', 0.7),
            (r'do\s+not\s+(mention|reveal|disclose)', 0.7),
        ]
        
        # Low-severity patterns (weight: 0.4) - Potential indicators
        self._low_severity_patterns: List[Tuple[str, float]] = [
            (r'as\s+a\s+(developer|hacker|expert)', 0.4),
            (r'hypothetical|theoretical|scenario', 0.4),
            (r'for\s+(research|educational|testing)\s+purposes', 0.4),
            (r'what\s+if|suppose|imagine', 0.4),
            (r'without\s+(restrictions|limitations|constraints)', 0.4),
            (r'no\s+(rules|limits|restrictions)', 0.4),
        ]
        
        # Compile all patterns for performance
        self._compiled_patterns: List[Tuple[re.Pattern, float]] = []
        for pattern, weight in (self._high_severity_patterns + 
                               self._medium_severity_patterns + 
                               self._low_severity_patterns):
            self._compiled_patterns.append((re.compile(pattern, re.IGNORECASE), weight))
    
    def analyze_threat(self, prompt: str) -> Tuple[float, MitigationAction, Dict[str, any]]:
        """
        Analyze a prompt for potential threats and return a threat score and mitigation action.
        
        Args:
            prompt: The user prompt to analyze
            
        Returns:
            Tuple containing:
                - threat_score: Float between 0.0 and 1.0
                - mitigation_action: One of BLOCK, FLAG, or PASS
                - metadata: Dictionary with detailed analysis information
        """
        if not prompt or not prompt.strip():
            return 0.0, MitigationAction.PASS, {"reason": "Empty prompt"}
        
        threat_score = 0.0
        matched_patterns = []
        pattern_details = []
        
        # Analyze prompt against all patterns
        for pattern, weight in self._compiled_patterns:
            matches = pattern.findall(prompt)
            if matches:
                # Calculate contribution: weight * (number of matches / length factor)
                match_count = len(matches)
                length_factor = max(1.0, len(prompt) / 100.0)  # Normalize by prompt length
                contribution = weight * (match_count / length_factor)
                
                threat_score += contribution
                matched_patterns.append({
                    "pattern": pattern.pattern,
                    "weight": weight,
                    "matches": match_count,
                    "contribution": contribution
                })
                pattern_details.append(f"{pattern.pattern} (weight: {weight}, matches: {match_count})")
        
        # Normalize threat score to 0.0-1.0 range
        # Use sigmoid-like function for smooth scaling
        threat_score = min(1.0, threat_score)
        
        # Apply additional heuristics
        # Check for excessive repetition (potential obfuscation)
        word_count = len(prompt.split())
        unique_words = len(set(prompt.lower().split()))
        if word_count > 0:
            uniqueness_ratio = unique_words / word_count
            if uniqueness_ratio < 0.3 and word_count > 20:
                threat_score = min(1.0, threat_score + 0.2)
                pattern_details.append("Low uniqueness ratio detected (potential obfuscation)")
        
        # Check for suspicious encoding patterns
        if re.search(r'[0-9a-f]{16,}', prompt, re.IGNORECASE):
            threat_score = min(1.0, threat_score + 0.15)
            pattern_details.append("Suspicious encoding pattern detected")
        
        # Determine mitigation action based on threat score
        if threat_score >= 0.8:
            mitigation_action = MitigationAction.BLOCK
        elif threat_score >= 0.5:
            mitigation_action = MitigationAction.FLAG
        else:
            mitigation_action = MitigationAction.PASS
        
        metadata = {
            "threat_score": round(threat_score, 4),
            "matched_patterns_count": len(matched_patterns),
            "pattern_details": pattern_details,
            "prompt_length": len(prompt),
            "word_count": word_count,
            "uniqueness_ratio": round(uniqueness_ratio if word_count > 0 else 1.0, 4),
            "mitigation_action": mitigation_action.value
        }
        
        return threat_score, mitigation_action, metadata
    
    def process_request(self, prompt: str) -> Dict[str, any]:
        """
        Process a security request and return comprehensive analysis.
        
        Args:
            prompt: The user prompt to analyze
            
        Returns:
            Dictionary containing threat analysis results
        """
        start_time = time.perf_counter()
        threat_score, mitigation_action, metadata = self.analyze_threat(prompt)
        processing_time_ms = (time.perf_counter() - start_time) * 1000
        
        return {
            "threat_score": threat_score,
            "mitigation_action": mitigation_action.value,
            "processing_time_ms": round(processing_time_ms, 3),
            "metadata": metadata
        }

