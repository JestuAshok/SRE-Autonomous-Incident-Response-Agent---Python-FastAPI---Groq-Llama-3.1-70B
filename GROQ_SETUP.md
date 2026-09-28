# Groq Integration Setup

## What Was Changed

The Incident Response Agent has been successfully migrated from Anthropic's Claude API to Groq API.

### Files Modified

1. **requirements.txt**
   - Replaced `anthropic>=0.18.0` with `groq>=0.4.0`
   - Added `python-dotenv>=1.0.0` for environment variable management

2. **agent/diagnosis_agent.py**
   - Renamed `ClaudeDiagnosisAgent` to `GroqDiagnosisAgent`
   - Updated imports to use Groq SDK
   - Modified tool definitions from Anthropic format to OpenAI-compatible format
   - Updated API client initialization to use Groq
   - Rewrote `_run_anthropic_loop()` as `_run_groq_loop()` with Groq's chat completion API

3. **agent/agent.py**
   - Updated import to use `GroqDiagnosisAgent`
   - Changed constructor parameter from `anthropic_api_key` to `groq_api_key`
   - Updated comments to reference Groq instead of Claude

4. **agent/__init__.py**
   - Updated exports to use `GroqDiagnosisAgent` and `GROQ_TOOLS`

5. **api/main.py**
   - Updated API endpoint docstring to reference Groq AI

6. **.env**
   - Created environment file for storing Groq API credentials

## Environment Setup

Add your Groq API key to the `.env` file:

```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.1-70b-versatile
```

## Running the Application

1. Activate the virtual environment:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

2. Start the server:
   ```powershell
   python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
   ```

3. Access the API:
   - Web UI: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Incidents List: http://localhost:8000/api/incidents

## Available Models

The Groq integration supports various models. You can configure them in `.env`:
- `llama-3.1-70b-versatile` (default)
- `llama-3.1-8b-instant`
- `mixtral-8x7b-32768`
- `gemma2-9b-it`

## API Features

The agent now uses Groq's LLM to:
- Analyze production incidents and alerts
- Correlate logs, metrics, and deployment history
- Generate root cause diagnoses
- Recommend remediation actions
- Provide forensic reasoning with tool-calling capabilities

## Tool Calling

The agent has access to three tools for incident investigation:
1. `read_logs` - Query service logs with filters
2. `get_deploy_history` - Retrieve deployment records
3. `get_metrics` - Fetch CPU, memory, and latency metrics

All tool definitions follow OpenAI's function calling format, which is compatible with Groq.
