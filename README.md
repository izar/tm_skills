# Agent skills to help with Continuous Threat Modeling

## Overview

These are agentic skills aimed at helping developers and security practitioners embody the methodology described in [Continuous Threat Modeling](https://github.com/izar/continuous-threat-modeling).

The skills available here try to follow the best practices described at [Agent Skills](https://skill.md) and shoulg be agnostic as to which agent they work with. YMMV, adjustments in path and location may be necessary. They have been tested with Anthropic's Claude Code and OpenAI Codex. 

The directory "examples" contain pre-generated threat models using different agents and models for the sake of comparison. These are not human-refined threat models.

## Skills Available

*pytm* - invoke with either /pytm or "threat model this codebase with pytm". This skill builds a pytm script describing your system, the sequence and DFD diagrams associated with it, and a business analysis of the intent of the system with a summary of the findings as well as a JSON file listing all the findings.

*ctm* - this skill takes a business request, a user-story or a developer story and establishes if it is a "security notable event" according to the Continuous Threat Modeling developer checklist. If it is, mitigations are suggested.

## Installation

Please refer to your agent's documentation for how to install these skills, as each one's paths vary.
