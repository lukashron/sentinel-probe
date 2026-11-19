up:
	@echo "Starting project..."
	docker compose up -d
	@echo "Project started successfully"

down:
	@echo "Stopping project..."
	docker compose down
	@echo "Project stopped successfully"

run:
	docker compose exec app php ./src/App.php
