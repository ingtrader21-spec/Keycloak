<#import "template.ftl" as layout>
<@layout.emailLayout>
  <p>Use this one-time code to verify your MoneyBee email address:</p>
  <p style="font-size:32px;font-weight:700;letter-spacing:8px;margin:24px 0">${code}</p>
  <p>This code expires in ${expiresInMinutes} minutes and can be used once.</p>
  <p>If you did not request this, you can ignore this message. Do not share this code with anyone.</p>
</@layout.emailLayout>
