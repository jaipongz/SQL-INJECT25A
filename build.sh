#!/bin/bash

echo "🚀 Starting backend (FastAPI)..."
cd backend
uvicorn main:app --reload --port 8000 &
BACKEND_PID=$!
cd ..

echo "🌐 Starting frontend (React)..."
cd frontend
npm start &
FRONTEND_PID=$!
cd ..

# Wait for processes
trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
