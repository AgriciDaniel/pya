ARG NODE_VERSION=20
FROM node:${NODE_VERSION}-alpine AS build
FROM php:8.3.30-fpm AS php
FROM python:3.12-slim AS py
FROM docker:29.9.2-dind AS dind
FROM node:22 AS floating
FROM gcr.io/distroless/nodejs22-debian12
