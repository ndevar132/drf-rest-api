from django.urls import path

from .views import ExpenseSummaryStats, IncomeSourcesSummaryStats


urlpatterns = [
    path('expense-category-data', ExpenseSummaryStats.as_view(),
         name='expense-category-summary'),
    path('income-sources-data', IncomeSourcesSummaryStats.as_view(),
         name='income-sources-data'),
]
