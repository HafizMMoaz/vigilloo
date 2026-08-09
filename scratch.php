<?php
class AppServiceProvider extends ServiceProvider {
    public function register() {
        $this->app->bind(PaymentGateway::class, StripeGateway::class);
        $this->app->singleton('reports', fn () => new ReportService());
    }
}
