import datetime

from rest_framework.views import APIView
from rest_framework import status, response

from expenses.models import Expense
from income.models import Income


class ExpenseSummaryStats(APIView):
    def get_category(self, expense):
        return expense.category

    def get_amount_for_category(self, expenses, category):
        expenses = expenses.filter(category=category)
        amount = 0
        for expense in expenses:
            amount += expense.amount

        return {
            'amount': str(amount)
        }

    def get(self, request):
        todays_date = datetime.date.today()
        ayear_ago = todays_date - datetime.timedelta(days=30*12)
        expenses = Expense.objects.filter(owner=request.user,
                                          date__gte=ayear_ago, date__lte=todays_date)

        final = {}
        categories = list(set(map(self.get_category, expenses)))

        for category in categories:
            final[category] = self.get_amount_for_category(expenses, category)

        return response.Response(
            {
                'category_data': final
            },
            status=status.HTTP_200_OK
        )


class IncomeSourcesSummaryStats(APIView):
    def get_source(self, income):
        return income.source

    def get_amount_for_source(self, incomes, source):
        incomes = incomes.filter(source=source)
        amount = 0
        for income in incomes:
            amount += income.amount

        return {
            'amount': str(amount)
        }

    def get(self, request):
        todays_date = datetime.date.today()
        ayear_ago = todays_date - datetime.timedelta(days=30*12)
        incomes = Income.objects.filter(owner=request.user,
                                        date__gte=ayear_ago, date__lte=todays_date)

        final = {}
        sources = list(set(map(self.get_source, incomes)))

        for source in sources:
            final[source] = self.get_amount_for_source(incomes, source)

        return response.Response(
            {
                'income_source_data': final
            },
            status=status.HTTP_200_OK
        )
