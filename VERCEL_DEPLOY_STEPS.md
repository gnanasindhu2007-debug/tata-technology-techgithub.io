# Vercel Deploy Steps

## Correct Project Root

In Vercel, the selected root folder must contain these files directly:

```text
app.py
model.py
report_generator.py
requirements.txt
vercel.json
api/index.py
templates/
static/
```

If these files are inside `outputs/deepshield_ai`, set the Vercel root directory
to:

```text
outputs/deepshield_ai
```

Or upload only the `vercel_ready_deepshield` folder as a fresh project.

## Redeploy

1. Go to Vercel project.
2. Open `Settings`.
3. Open `General`.
4. Set `Root Directory` to `outputs/deepshield_ai` if using this full repo.
5. Save.
6. Go to `Deployments`.
7. Click `Redeploy`.
8. Disable `Use existing Build Cache`.
9. Redeploy.

## Why The Error Happened

The 500 error happened because Vercel could not import the Flask app using the
old deployment structure. This project now uses `api/index.py`, which is the
recommended serverless entry point pattern for Flask on Vercel.
