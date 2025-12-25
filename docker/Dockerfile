FROM python:3.9-alpine

# Créer un utilisateur non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copier les fichiers
COPY ../api/app.py .
COPY ../api/requirements.txt .

# Installer les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Changer les permissions
RUN chown -R appuser:appgroup /app

# Utiliser l'utilisateur non-root
USER appuser

EXPOSE 5000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

CMD ["python", "app.py"]