# Canary Tracker

A Burp Suite extension for detecting and tracking first- and second-order canary values in web application traffic.

This extension injects non-sensitive canary markers into eligible request parameters, watches for them to appear in subsequent responses, and records the originating request context and the observed context where the marker reappears. It is designed to help identify reflections, cross-context leakage, and second-order data exposure in application flows.

## What it does

- Injects unique marker tokens like `zx7f3k_<id>_<index>` into eligible request parameters
- Avoids modifying cookies and common credential/CSRF/session-related parameters
- Tracks where each marker originated and in which context it was observed
- Detects:
  - first-order reflection
  - cross-context exposure
  - second-order resurfacing
- Persists marker state and findings in Burp's extension settings
- Exposes a UI table with findings and controls for active context/session labeling

## Why use it

When testing for web security issues such as:

- reflected input in responses
- data flowing across application roles or sessions
- hidden state resurfacing from earlier requests
- sensitive values being reintroduced into unrelated contexts

canary tracking provides a practical way to notice whether a marker inserted in one request reappears elsewhere.

## Features

- Active role/session tracking via a configurable label
- Optional in-scope-only injection
- Request context selection from a chosen Burp message
- Findings table with:
  - finding type
  - canary value
  - parameter name
  - origin URL
  - origin context
  - seen URL
  - observed context
  - timestamp
- Built-in state cleanup using clear findings and reset tracking

## Supported environment

- Burp Suite
- Jython-based Burp extension
- Python compatibility for the Burp legacy Jython API

## Installation

1. Open Burp Suite.
2. Go to Extender > Extensions.
3. Add a new extension using the Python/Jython environment supported by your Burp installation.
4. Load `canary_tracker.py`.
5. The extension will register a tab named `Canary Tracker` in Burp.

## Usage

### 1. Configure the active context

Use the `Active role/session` field or the `Set context` button to label the current workflow or application role, such as:

- `default`
- `admin`
- `user-a`
- `partner-api`

### 2. Enable injection

Check `Inject into eligible Proxy parameters (active scope only)` to allow the extension to insert markers into eligible request parameters.

By default, the extension does not inject markers unless explicitly enabled.

### 3. Choose in-scope behavior

Use `In-scope only` to restrict injection to requests that are in Burp's active scope.

### 4. Observe findings

As requests are sent and responses are analyzed, the extension lists any canaries that appear in responses and classifies them based on how they resurfaced.

### 5. Clear data when needed

Use `Clear findings` to remove saved tracking data and reset stored marker state.

## Important behavior

This extension intentionally ignores:

- cookies
- common credential fields
- session and CSRF-related names
- other sensitive parameter names

This is intended to reduce risk of tampering with authentication or session handling while tracking flow behavior.

## Limitations

- The extension is designed for Burp's legacy Jython API and depends on the Burp environment.
- It only injects markers into eligible parameters and will not modify every request field.
- It tracks findings in memory and persists state in Burp settings, so large volumes of traffic may require periodic cleanup.

## File overview

- `canary_tracker.py` — main Burp extension logic
- `README.md` — project documentation

## License

This project does not currently declare a repository license. If you intend to redistribute or publish this extension, add a license file before broader distribution.

## Notes

This tool is useful during manual security testing and API analysis workflows where understanding how data moves across requests, roles, and contexts is essential.
