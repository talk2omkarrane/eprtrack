# EPRTrack V12 — EPR Data Analyzer

V12 changes the product direction from a manual tracking dashboard to a data-first EPR workflow. The new public analyzer lets a user upload an Excel/CSV file, review automatic column mapping, detect data-quality problems and download a reviewed spreadsheet with excluded rows highlighted and an `Error / Reason` column.

## V12 workflow
1. Download the EPRTrack Excel template or sample file.
2. Upload Excel or CSV.
3. Automatically map common column names.
4. Review/edit mappings.
5. Analyse rows for duplicates, missing packaging data, invalid quantities, invalid dates, unsupported units, category mapping problems and suspicious packaging weights.
6. Show an EPR Health Check.
7. Download a reviewed Excel with problematic rows highlighted in red and a reason column.
8. Download a CSV issue list or sample report.

## Recommended upload columns
- Invoice No
- Product
- Quantity
- Quantity Unit
- Invoice Date
- Packaging Type
- Packaging Weight (kg)
- EPR Category

The analyzer accepts common alternatives and lets the user correct mappings. V12 supports kg and tonnes as transaction quantity units.

## Privacy model
V12 file analysis is browser-side. Uploaded files are not sent to the EPRTrack Worker in this version. The last health-check summary is stored only in browser localStorage so the dashboard can show the latest local result. V13 should move saved analysis results into D1 after the core workflow is validated.

## Planning/regulatory boundary
The analyzer is a data-quality and planning workflow. Its packaging-quantity view is **not** a legal EPR target determination and does not certify fulfilment. It must not be presented as replacing CPCB/Common EPR Portal records or current regulatory requirements. The official plastic EPR portal states that its operations were discontinued from 28 June 2026 and that users should use the Common EPR Portal for current updates.

Official source: https://www.eprplastic.cpcb.gov.in/

## V11/V10 compatibility
- Existing auth/D1/company/compliance/task workflows are retained.
- Existing manual tracking remains available as a supporting workflow.
- New dashboard messaging points users to the data analyzer as the primary workflow.
- Payments remain disabled.
- Do not replace the real `wrangler.jsonc` or D1 binding.

## Included downloadable examples
- `public/eprtrack_epr_upload_template.xlsx` — recommended Excel format with a clean sample sheet.
- `public/eprtrack_epr_sample_data.csv` — deliberately mixed sample containing valid and invalid rows.
- `public/eprtrack_sample_reviewed_output.xlsx` — example of the reviewed output with red-highlighted excluded rows and an Error / Reason column.
- `public/eprtrack_sample_epr_health_report.pdf` — human-readable sample health report.

## Next product stage
V13 should connect the validated business data to the EPR reconciliation engine: company role/category + historical business data + evidence/certificates + versioned rules → an automatic, traceable compliance position.
