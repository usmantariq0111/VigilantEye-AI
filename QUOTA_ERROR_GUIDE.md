# Quota Error Guide - Fixing API Rate Limits

## Understanding the Error

If you see errors like:
```
429 You exceeded your current quota
Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_input_token_count
```

This means your API key has hit rate limits. This typically happens when:

1. **Free Tier Limits**: PRO models (`gemini-2.5-pro`, `gemini-1.5-pro`) have **zero quota on the free tier**
2. **Rate Limits**: You've exceeded requests per minute/day
3. **Billing Not Enabled**: PRO models require a paid plan with billing enabled

## Solutions

### Option 1: Enable Billing (Recommended for PRO Accounts)

If you have a PRO account but still see quota errors:

1. **Go to Google Cloud Console**: https://console.cloud.google.com/
2. **Select your project** (or create one)
3. **Enable Billing**:
   - Go to "Billing" in the left menu
   - Link a billing account
   - Add a payment method
4. **Enable Gemini API**:
   - Go to "APIs & Services" > "Library"
   - Search for "Generative Language API"
   - Click "Enable"
5. **Check Quotas**:
   - Go to "APIs & Services" > "Quotas"
   - Search for "Generative Language API"
   - Verify your quotas are set correctly

### Option 2: Use Flash Models (Free Tier Friendly)

The application **automatically falls back to Flash models** when PRO models hit quota limits:

- `gemini-2.5-flash` - Fast, good quality, higher free tier limits
- `gemini-1.5-flash` - Widely available, good free tier support
- `gemini-2.0-flash` - Stable alternative

Flash models have:
- ✅ Higher free tier quotas
- ✅ Faster responses
- ✅ Lower costs
- ⚠️ Slightly less detailed than PRO models

### Option 3: Wait for Rate Limit Reset

Rate limits reset:
- **Per Minute**: Resets every 60 seconds
- **Per Day**: Resets at midnight (your timezone)

Check your current usage: https://ai.dev/usage

## Automatic Handling

The application now includes:

1. **Automatic Retry**: Retries with exponential backoff when rate limits are hit
2. **Automatic Fallback**: Switches to Flash models if PRO models fail
3. **Better Error Messages**: Clear guidance on what went wrong

## Model Priority (Updated)

The app tries models in this order:

1. **PRO Models** (if you have paid plan):
   - `gemini-2.5-pro` 
   - `gemini-3-pro-preview`
   - `gemini-1.5-pro`

2. **Flash Models** (automatic fallback):
   - `gemini-2.5-flash`
   - `gemini-1.5-flash`
   - `gemini-2.0-flash`

## Verification

After enabling billing, verify:

1. **Check API Status**: https://status.cloud.google.com/
2. **Test API Key**: Use Google AI Studio to test your key
3. **Monitor Usage**: https://ai.dev/usage
4. **Check Console**: Look for model selection messages:
   ```
   [Intelligence Engine] Using model: gemini-2.5-pro
   ```

## Troubleshooting

### Still Getting Quota Errors After Enabling Billing?

1. **Wait 5-10 minutes** for changes to propagate
2. **Verify API is enabled** in Google Cloud Console
3. **Check project selection** - ensure correct project is selected
4. **Verify API key** is from the correct project
5. **Check billing account** is active and linked

### Flash Models Also Hitting Limits?

1. **Reduce request frequency** - wait between requests
2. **Check daily limits** - you may have exceeded daily quota
3. **Upgrade plan** if you need higher limits
4. **Use batch processing** for multiple files

## Rate Limit Information

### Free Tier Limits (Approximate)
- **Flash Models**: 15 requests/minute, 1,500 requests/day
- **PRO Models**: 0 requests (not available on free tier)

### Paid Tier Limits
- **Flash Models**: Higher limits based on your plan
- **PRO Models**: Available with paid plan

## Need Help?

- **Google AI Studio**: https://aistudio.google.com/
- **API Documentation**: https://ai.google.dev/gemini-api/docs
- **Rate Limits**: https://ai.google.dev/gemini-api/docs/rate-limits
- **Usage Dashboard**: https://ai.dev/usage

## Quick Fix Summary

1. ✅ **Enable billing** in Google Cloud Console
2. ✅ **Enable Generative Language API**
3. ✅ **Wait 5-10 minutes** for propagation
4. ✅ **Restart Flask app**
5. ✅ **App will automatically use PRO models** if available, or fall back to Flash

The application is now smart enough to handle quota errors gracefully and automatically fall back to working models!

