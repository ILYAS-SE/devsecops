FROM python:3.9-alpine

WORKDIR /app

# Créer un utilisateur non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copier les fichiers
COPY api/app.py .

# Installer les dépendances
RUN pip install --no-cache-dir flask bcrypt

# Créer le répertoire data
RUN mkdir /app/data && chown -R appuser:appgroup /app

# Utiliser l'utilisateur non-root
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]