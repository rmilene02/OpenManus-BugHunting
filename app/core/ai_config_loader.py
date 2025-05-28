"""
AI Configuration Loader Module

This module loads and manages AI configuration from modular TOML files,
allowing for customizable prompts, tools, wordlists, and rules.
"""

import os
import toml
from typing import Dict, List, Any, Optional
from pathlib import Path
from app.logger import logger


class AIConfigLoader:
    """
    Loads and manages AI configuration from modular TOML files.
    Supports custom configurations and user-specific rules.
    """
    
    def __init__(self, config_base_path: str = "config/ai"):
        """
        Initialize the AI configuration loader.
        
        Args:
            config_base_path: Base path for AI configuration files
        """
        self.config_base_path = Path(config_base_path)
        self.prompts_config = {}
        self.tools_config = {}
        self.wordlists_config = {}
        self.ai_config = {}
        self.custom_rules = {}
        
        self._load_all_configs()
    
    def _load_all_configs(self):
        """Load all AI configuration files."""
        try:
            self._load_prompts_config()
            self._load_tools_config()
            self._load_wordlists_config()
            self._load_ai_config()
            self._load_custom_rules()
            logger.info("AI configuration loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load AI configuration: {e}")
            raise
    
    def _load_prompts_config(self):
        """Load prompts configuration from prompts.toml."""
        prompts_file = self.config_base_path / "prompts.toml"
        if prompts_file.exists():
            self.prompts_config = toml.load(prompts_file)
            logger.debug(f"Loaded prompts configuration from {prompts_file}")
        else:
            logger.warning(f"Prompts configuration file not found: {prompts_file}")
    
    def _load_tools_config(self):
        """Load tools configuration from tools.toml."""
        tools_file = self.config_base_path / "tools.toml"
        if tools_file.exists():
            self.tools_config = toml.load(tools_file)
            logger.debug(f"Loaded tools configuration from {tools_file}")
        else:
            logger.warning(f"Tools configuration file not found: {tools_file}")
    
    def _load_wordlists_config(self):
        """Load wordlists configuration from wordlists.toml."""
        wordlists_file = self.config_base_path / "wordlists.toml"
        if wordlists_file.exists():
            self.wordlists_config = toml.load(wordlists_file)
            logger.debug(f"Loaded wordlists configuration from {wordlists_file}")
        else:
            logger.warning(f"Wordlists configuration file not found: {wordlists_file}")
    
    def _load_ai_config(self):
        """Load main AI configuration from config.toml."""
        ai_config_file = self.config_base_path / "config.toml"
        if ai_config_file.exists():
            self.ai_config = toml.load(ai_config_file)
            logger.debug(f"Loaded AI configuration from {ai_config_file}")
        else:
            logger.warning(f"AI configuration file not found: {ai_config_file}")
    
    def _load_custom_rules(self):
        """Load custom rules from custom/rules directory."""
        custom_rules_dir = self.config_base_path / "custom" / "rules"
        if custom_rules_dir.exists():
            for rules_file in custom_rules_dir.glob("*.toml"):
                try:
                    custom_config = toml.load(rules_file)
                    self.custom_rules[rules_file.stem] = custom_config
                    logger.debug(f"Loaded custom rules from {rules_file}")
                except Exception as e:
                    logger.error(f"Failed to load custom rules from {rules_file}: {e}")
    
    def get_system_prompt(self, include_custom_rules: bool = True) -> str:
        """
        Get the complete system prompt for AI tool selection.
        
        Args:
            include_custom_rules: Whether to include custom rules in the prompt
            
        Returns:
            Complete system prompt string
        """
        prompt_parts = []
        
        # Base system prompt
        if "system_prompts" in self.prompts_config:
            if "tool_selection" in self.prompts_config["system_prompts"]:
                prompt_parts.append(self.prompts_config["system_prompts"]["tool_selection"])
        
        # Bug hunting rules
        if "system_prompts" in self.prompts_config:
            if "bug_hunting_rules" in self.prompts_config["system_prompts"]:
                prompt_parts.append("\n" + self.prompts_config["system_prompts"]["bug_hunting_rules"])
        
        # Reconnaissance guidelines
        if "system_prompts" in self.prompts_config:
            if "reconnaissance_guidelines" in self.prompts_config["system_prompts"]:
                prompt_parts.append("\n" + self.prompts_config["system_prompts"]["reconnaissance_guidelines"])
        
        # Custom rules if requested
        if include_custom_rules and self.custom_rules:
            prompt_parts.append("\n\nCUSTOM RULES AND CONFIGURATIONS:")
            for rule_name, rule_config in self.custom_rules.items():
                if "custom_ai_instructions" in rule_config:
                    instructions = rule_config["custom_ai_instructions"]
                    if "focus_areas" in instructions:
                        prompt_parts.append(f"\nFocus Areas for {rule_name}:")
                        for area in instructions["focus_areas"]:
                            prompt_parts.append(f"- {area}")
                    
                    if "avoid_areas" in instructions:
                        prompt_parts.append(f"\nAvoid Areas for {rule_name}:")
                        for area in instructions["avoid_areas"]:
                            prompt_parts.append(f"- {area}")
                    
                    if "special_considerations" in instructions:
                        prompt_parts.append(f"\nSpecial Considerations for {rule_name}:")
                        for consideration in instructions["special_considerations"]:
                            prompt_parts.append(f"- {consideration}")
        
        return "\n".join(prompt_parts)
    
    def get_available_tools(self) -> Dict[str, Any]:
        """
        Get available tools configuration.
        
        Returns:
            Dictionary of available tools organized by category
        """
        available_tools = {}
        
        # Process each tool category
        for category in ["subdomain_enumeration", "web_discovery", "network_scanning", 
                        "vulnerability_scanning", "directory_enumeration", "osint"]:
            if category in self.tools_config:
                available_tools[category] = {}
                for tool_name, tool_config in self.tools_config[category].items():
                    if isinstance(tool_config, dict) and "name" in tool_config:
                        available_tools[category][tool_name] = tool_config
        
        return available_tools
    
    def get_wordlists_for_target(self, target_type: str, scan_mode: str, 
                                time_constraint: str = "normal") -> List[Dict[str, Any]]:
        """
        Get recommended wordlists for a specific target and scan mode.
        
        Args:
            target_type: Type of target (web_application, api, etc.)
            scan_mode: Scanning mode (reconnaissance, comprehensive, etc.)
            time_constraint: Time constraint (fast, normal, thorough)
            
        Returns:
            List of recommended wordlist configurations
        """
        recommended_wordlists = []
        
        if "selection_rules" not in self.wordlists_config:
            return recommended_wordlists
        
        # Get rules based on time constraint
        rules_key = f"{time_constraint}_scan"
        if rules_key in self.wordlists_config["selection_rules"]:
            rules = self.wordlists_config["selection_rules"][rules_key]
            max_requests = rules.get("max_requests", 10000)
            preferred_lists = rules.get("preferred_wordlists", [])
            
            total_requests = 0
            
            # Add preferred wordlists
            for wordlist_name in preferred_lists:
                wordlist_config = self._find_wordlist_config(wordlist_name)
                if wordlist_config:
                    estimated_requests = wordlist_config.get("estimated_requests", 1000)
                    if total_requests + estimated_requests <= max_requests:
                        recommended_wordlists.append(wordlist_config)
                        total_requests += estimated_requests
        
        return recommended_wordlists
    
    def _find_wordlist_config(self, wordlist_name: str) -> Optional[Dict[str, Any]]:
        """
        Find wordlist configuration by name.
        
        Args:
            wordlist_name: Name of the wordlist to find
            
        Returns:
            Wordlist configuration dictionary or None if not found
        """
        # Search in all wordlist categories
        for category in ["directory_wordlists", "api_wordlists", "subdomain_wordlists",
                        "technology_specific", "parameter_wordlists", "backup_files",
                        "custom_wordlists"]:
            if category in self.wordlists_config:
                for name, config in self.wordlists_config[category].items():
                    if name == wordlist_name or config.get("name", "").lower() == wordlist_name.lower():
                        return config
        
        return None
    
    def get_tool_selection_rules(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get tool selection rules based on scan context.
        
        Args:
            scan_context: Context information about the scan
            
        Returns:
            Tool selection rules and preferences
        """
        rules = {}
        
        # Get base rules from tools config
        if "selection_rules" in self.tools_config:
            base_rules = self.tools_config["selection_rules"]
            
            # Apply rules based on scan mode
            if scan_context.get("stealth_mode", False) and "stealth_mode" in base_rules:
                rules.update(base_rules["stealth_mode"])
            elif scan_context.get("time_constraint") == "fast" and "fast_scan" in base_rules:
                rules.update(base_rules["fast_scan"])
            elif scan_context.get("deep_scan", False) and "comprehensive_scan" in base_rules:
                rules.update(base_rules["comprehensive_scan"])
            elif scan_context.get("passive_only", False) and "passive_only" in base_rules:
                rules.update(base_rules["passive_only"])
        
        # Apply custom rules if available
        for rule_name, rule_config in self.custom_rules.items():
            if "custom_tool_preferences" in rule_config:
                custom_prefs = rule_config["custom_tool_preferences"]
                if "preferred_subdomain_tools" in custom_prefs:
                    rules["preferred_subdomain_tools"] = custom_prefs["preferred_subdomain_tools"]
                if "preferred_directory_tools" in custom_prefs:
                    rules["preferred_directory_tools"] = custom_prefs["preferred_directory_tools"]
                if "preferred_vulnerability_tools" in custom_prefs:
                    rules["preferred_vulnerability_tools"] = custom_prefs["preferred_vulnerability_tools"]
        
        return rules
    
    def get_compliance_requirements(self) -> Dict[str, Any]:
        """
        Get compliance requirements from configuration.
        
        Returns:
            Dictionary of compliance requirements and frameworks
        """
        compliance = {}
        
        # Get base compliance from prompts config
        if "compliance_frameworks" in self.prompts_config:
            compliance.update(self.prompts_config["compliance_frameworks"])
        
        # Add custom compliance requirements
        for rule_name, rule_config in self.custom_rules.items():
            if "custom_compliance" in rule_config:
                custom_compliance = rule_config["custom_compliance"]
                compliance[f"custom_{rule_name}"] = custom_compliance
        
        return compliance
    
    def get_reporting_config(self) -> Dict[str, Any]:
        """
        Get reporting configuration.
        
        Returns:
            Dictionary of reporting configuration
        """
        reporting_config = {}
        
        # Get base reporting config
        if "reporting" in self.ai_config:
            reporting_config.update(self.ai_config["reporting"])
        
        # Get reporting guidelines from prompts
        if "reporting_guidelines" in self.prompts_config:
            reporting_config["guidelines"] = self.prompts_config["reporting_guidelines"]
        
        # Add custom reporting preferences
        for rule_name, rule_config in self.custom_rules.items():
            if "custom_reporting" in rule_config:
                custom_reporting = rule_config["custom_reporting"]
                reporting_config[f"custom_{rule_name}"] = custom_reporting
        
        return reporting_config
    
    def reload_configs(self):
        """Reload all configuration files."""
        logger.info("Reloading AI configuration files")
        self._load_all_configs()
    
    def validate_config(self) -> bool:
        """
        Validate the loaded configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Check if essential configurations are loaded
            if not self.prompts_config:
                logger.error("Prompts configuration is empty")
                return False
            
            if not self.tools_config:
                logger.error("Tools configuration is empty")
                return False
            
            if not self.wordlists_config:
                logger.error("Wordlists configuration is empty")
                return False
            
            # Validate required sections
            required_prompt_sections = ["system_prompts", "bug_hunting_rules"]
            for section in required_prompt_sections:
                if section not in self.prompts_config:
                    logger.warning(f"Missing required prompt section: {section}")
            
            required_tool_categories = ["subdomain_enumeration", "web_discovery", "vulnerability_scanning"]
            for category in required_tool_categories:
                if category not in self.tools_config:
                    logger.warning(f"Missing required tool category: {category}")
            
            logger.info("AI configuration validation completed")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False