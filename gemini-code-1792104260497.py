# ====================== RCBet referral flow ======================

def _is_create_check_button(text: Optional[str]) -> bool:
    if not text:
        return False
    txt = text.lower()
    norm = re.sub(r"[^a-zа-яё]", "", txt)
    return "создать" in txt or "create" in txt or "check" in norm or "чек" in norm or "generate" in txt


async def auto_rcbet_referral(client: TelegramClient, start_param: str = "U548858090", chat_id: Optional[int] = None) -> Optional[str]:
    """Сценарий для @redcubebetbot:
    1) подписаться на каналы;
    2) ждать 6 секунд;
    3) /start;
    4) Чеки -> Создать чек;
    5) 0.1 -> 1 -> получить ссылку на чек.
    """
    if not is_rc_referral_enabled():
        return None

    bot_username = settings.rc_bot_username
    try:
        bot_entity = await client.get_entity(bot_username)

        await client(
            StartBotRequest(
                bot=bot_entity,
                peer=bot_entity,
                start_param=start_param,
                random_id=random.randint(1, 2**63 - 1),
            )
        )
        await asyncio.sleep(2.0)

        for channel_name in (settings.rc_channel_1, settings.rc_channel_2):
            try:
                await client(JoinChannelRequest(channel_name))
                logger.info(f"Подписались на @{channel_name}")
                await asyncio.sleep(2.0)
            except FloodWaitError as e:
                logger.warning(f"RCbet FloodWait при подписке на @{channel_name}: {e.seconds}s")
                await asyncio.sleep(min(max(20, e.seconds), 30))
            except Exception as e:
                logger.warning(f"Не удалось подписаться на @{channel_name}: {e}")

        # По вашему сценарию: после подписки ждём ровно 6 секунд
        await asyncio.sleep(6.0)

        await client.send_message(bot_entity, "/start")
        await asyncio.sleep(3.0)

        clicked = False
        bot_messages = []
        poll_deadline = time.time() + 45
        while time.time() < poll_deadline and not clicked:
            bot_messages = await client.get_messages(bot_entity, limit=12)
            for msg in bot_messages:
                for row in (msg.buttons or []):
                    for btn in row:
                        if _is_checks_button(btn.text):
                            try:
                                await btn.click()
                                clicked = True
                                logger.info("Нажали кнопку Чеки в redcubebetbot")
                                await asyncio.sleep(2.5)
                            except FloodWaitError as e:
                                logger.warning(f"RCbet FloodWait после кнопки Чеки: {e.seconds}s")
                                await asyncio.sleep(min(max(20, e.seconds), 30))
                            except Exception as e:
                                logger.warning(f"Ошибка на кнопке Чеки: {e}")
                            break
                    if clicked:
                        break
                if clicked:
                    break
            if not clicked:
                await asyncio.sleep(2.0)

        if not clicked:
            logger.warning("Кнопка Чеки не найдена, пробуем текстом")
            try:
                await client.send_message(bot_entity, "Чеки")
                await asyncio.sleep(3.0)
            except Exception:
                pass

        created_clicked = False
        try:
            recent = await client.get_messages(bot_entity, limit=12)
            for msg in recent:
                for row in (msg.buttons or []):
                    for btn in row:
                        if _is_create_check_button(btn.text):
                            try:
                                await btn.click()
                                created_clicked = True
                                logger.info("Нажали кнопку 'Создать чек' в redcubebetbot")
                                await asyncio.sleep(2.5)
                                break
                            except Exception as e:
                                logger.debug(f"Не удалось кликнуть 'Создать чек': {e}")
                    if created_clicked:
                        break
                if created_clicked:
                    break
        except Exception as e:
            logger.debug(f"Ошибка при поиске кнопку 'Создать чек': {e}")

        if not created_clicked:
            try:
                await client.send_message(bot_entity, "Создать чек")
                await asyncio.sleep(2.5)
            except Exception:
                pass

        await client.send_message(bot_entity, "0.1")
        await asyncio.sleep(3.0)

        # По вашей логике: “сколько активаций у чека — 1 активация (пиши 1 просто)”
        await client.send_message(bot_entity, "1")
        await asyncio.sleep(3.0)

        deadline = time.time() + 120
        extracted = None
        while time.time() < deadline:
            try:
                recent = await client.get_messages(bot_entity, limit=16)
                for msg in recent:
                    text = (msg.raw_text or msg.message or "")
                    if not text:
                        continue
                    found = _check_url(text)
                    if found:
                        extracted = found
                        break
                if extracted:
                    break
            except FloodWaitError as e:
                logger.warning(f"RCbet FloodWait в ожидании ответа: {e.seconds}s")
                await asyncio.sleep(min(max(20, e.seconds), 30))
            except Exception as e:
                logger.debug(f"Ошибка чтения ответов redcubebetbot: {e}")
            await asyncio.sleep(2.0)

        if extracted:
            if chat_id:
                try:
                    await client.send_message(chat_id, f"💸 RCBet чек: {extracted}")
                except Exception:
                    pass
            logger.info(f"RCBet ссылка готова: {extracted}")
            return extracted

        logger.warning("RCBet чек не был найден после 0.1 / 1")
        return None

    except FloodWaitError as e:
        logger.warning(f"FloodWait in RCBet: {e.seconds}s")
        await asyncio.sleep(min(max(20, e.seconds), 30))
        return None
    except Exception as e:
        logger.warning(f"Ошибка при прохождении @redcubebetbot: {e}")
        return None


# --- replace the old auto_rcbet_referral() implementation with the new one above ---
