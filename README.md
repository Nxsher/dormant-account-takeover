# dormant-account-takeover
SQL analysis of dormant-account reactivation and potential account takeover patterns

WITH transaction_history AS (
    SELECT
        transac_info.account_id,
        transac_info.transaction_id,
        transac_info.event_date,
        transac_info.device_id,
        transac_info.ip_address,
        transac_info.card_id,
        transac_info.amount,
        card_data.cardholder_first_name,
        card_data.cardholder_last_name,

        LAG(transac_info.event_date) OVER (
            PARTITION BY transac_info.account_id
            ORDER BY transac_info.event_date
        ) AS previous_event_date

    FROM transac_info

    LEFT JOIN card_data
        ON transac_info.card_id = card_data.card_id
),


reactivated_accounts AS (
    SELECT
        *,
        julianday(event_date)
        - julianday(previous_event_date) AS dormant_days

    FROM transaction_history

    WHERE julianday(event_date)
        - julianday(previous_event_date) > 365
),


identity_checks AS (
    SELECT
        reactivated_accounts.*,

        CASE
            WHEN EXISTS (
                SELECT 1
                FROM transaction_history AS previous_history
                WHERE previous_history.account_id =
                      reactivated_accounts.account_id

                  AND previous_history.device_id =
                      reactivated_accounts.device_id

                  AND previous_history.event_date <
                      reactivated_accounts.event_date
            )
            THEN 0
            ELSE 1
        END AS new_device,

        CASE
            WHEN EXISTS (
                SELECT 1
                FROM transaction_history AS previous_history
                WHERE previous_history.account_id =
                      reactivated_accounts.account_id

                  AND previous_history.ip_address =
                      reactivated_accounts.ip_address

                  AND previous_history.event_date <
                      reactivated_accounts.event_date
            )
            THEN 0
            ELSE 1
        END AS new_ip,

        CASE
            WHEN EXISTS (
                SELECT 1
                FROM transaction_history AS previous_history
                WHERE previous_history.account_id =
                      reactivated_accounts.account_id

                  AND previous_history.card_id =
                      reactivated_accounts.card_id

                  AND previous_history.event_date <
                      reactivated_accounts.event_date
            )
            THEN 0
            ELSE 1
        END AS new_card,

        CASE
            WHEN EXISTS (
                SELECT 1
                FROM transaction_history AS previous_history
                WHERE previous_history.account_id =
                      reactivated_accounts.account_id

                  AND previous_history.cardholder_first_name =
                      reactivated_accounts.cardholder_first_name

                  AND previous_history.cardholder_last_name =
                      reactivated_accounts.cardholder_last_name

                  AND previous_history.event_date <
                      reactivated_accounts.event_date
            )
            THEN 0
            ELSE 1
        END AS new_cardholder_name

    FROM reactivated_accounts
),


suspicious_reactivations AS (
    SELECT *
    FROM identity_checks

    WHERE new_device = 1
      AND new_ip = 1
      AND new_card = 1
      AND new_cardholder_name = 1
),


post_reactivation_purchases AS (
    SELECT
        transac_info.account_id,
        transac_info.transaction_id,
        transac_info.event_date,
        transac_info.amount,

        suspicious_reactivations.event_date AS reactivation_date,

        LAG(transac_info.amount) OVER (
            PARTITION BY transac_info.account_id
            ORDER BY transac_info.event_date
        ) AS previous_amount,

        LAG(transac_info.event_date) OVER (
            PARTITION BY transac_info.account_id
            ORDER BY transac_info.event_date
        ) AS previous_purchase_date

    FROM transac_info

    INNER JOIN suspicious_reactivations
        ON transac_info.account_id =
           suspicious_reactivations.account_id

    WHERE transac_info.event_date >=
          suspicious_reactivations.event_date
),


purchase_behavior AS (
    SELECT
        *,

        (julianday(event_date)
        - julianday(previous_purchase_date)) * 24
        AS hours_since_previous_purchase,

        CASE
            WHEN amount > previous_amount
            THEN 1
            ELSE 0
        END AS amount_increased,

        CASE
            WHEN (
                julianday(event_date)
                - julianday(previous_purchase_date)
            ) * 24 >= 24
            THEN 1
            ELSE 0
        END AS spaced_24_hours

    FROM post_reactivation_purchases
)

SELECT *
FROM purchase_behavior

WHERE amount_increased = 1
  AND spaced_24_hours = 1

ORDER BY account_id, event_date;
