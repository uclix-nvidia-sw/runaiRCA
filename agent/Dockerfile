FROM python:3.12-slim AS dependencies

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Runtime and build requirements change much less often than the agent source.
# Keeping this layer manifest-only lets ordinary Python/knowledge/prompt edits
# reuse the expensive dependency installation layer.
RUN python -m venv "$VIRTUAL_ENV"
COPY pyproject.toml ./
RUN python -c 'import pathlib, subprocess, sys, tomllib; config = tomllib.loads(pathlib.Path("pyproject.toml").read_text()); requirements = [*config["build-system"]["requires"], *config["project"]["dependencies"]]; subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", *requirements])'

FROM dependencies AS build

COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir --no-deps --no-build-isolation .

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY --from=build /opt/venv /opt/venv
COPY configs ./configs
COPY knowledge ./knowledge
COPY prompts ./prompts
COPY ontology ./ontology
COPY eval ./eval

RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
