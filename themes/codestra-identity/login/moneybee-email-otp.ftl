<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
  <#if section == "header">
    Verify your email
  <#elseif section == "form">
    <form id="kc-moneybee-otp-form" action="${url.loginAction}" method="post">
      <p>We sent a 6-digit verification code to <strong>${maskedEmail}</strong>.</p>
      <#if moneybeeOtpMessage??><p role="status">${moneybeeOtpMessage}</p></#if>
      <div class="pf-v5-c-form__group">
        <label for="code">Verification code</label>
        <input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required autofocus />
      </div>
      <p>The current code expires in about ${(expiresInSeconds / 60)?ceiling} minute(s).</p>
      <button type="submit" name="action" value="verify">Verify email</button>
      <button type="submit" name="action" value="resend" formnovalidate>Send a new code</button>
      <#if resendWaitSeconds gt 0><p>You can request another code in ${resendWaitSeconds} seconds.</p></#if>
    </form>
  </#if>
</@layout.registrationLayout>
