FROM apache/superset:3.0.0

#ARG IMAGEREPOSITORY
#FROM $IMAGEREPOSITORY AS build

COPY superset_config.py /app/pythonpath
COPY AnalyticXploreUpdated.png /app/superset/static/assets/images/AnalyticXploreUpdated.png
COPY excel.py /app/superset/utils
RUN pip install psycopg
RUN pip install prophet
