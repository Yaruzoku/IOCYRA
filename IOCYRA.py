import asyncio
import os
import re
import tempfile
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

from url_analyzer import analyze as analyze_url
from file_analyzer import analyze_file
from archive_analyzer import analyze_archive


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

GUILD_ID = 1254457288723533894
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")

MAX_FILE_SIZE = 500 * 1024 * 1024

GUILD = discord.Object(
    id=GUILD_ID
)

URL_PATTERN = re.compile(
    r"https?://\S+",
    re.IGNORECASE
)


# ============================================================
# DISCORD SETUP
# ============================================================

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(
    command_prefix="!",
    intents=intents
)


# ============================================================
# HELPERS
# ============================================================

def format_file_size(size):

    units = [
        "B",
        "KB",
        "MB",
        "GB"
    ]

    value = float(size)

    for unit in units:

        if (
            value < 1024
            or unit == units[-1]
        ):
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} GB"


def truncate(
    text,
    limit=1024
):

    if text is None:
        return ""

    text = str(text)

    if len(text) <= limit:
        return text

    return text[:limit - 3] + "..."


def clean_url(url):

    return url.rstrip(
        ".,!?;:)]}>"
    )


def extract_url(text):

    if not text:
        return None

    match = URL_PATTERN.search(
        text
    )

    if not match:
        return None

    return clean_url(
        match.group(0)
    )


def get_triage_color(level):

    colors = {
        "MINIMAL":
            discord.Color.green(),

        "LOW":
            discord.Color.yellow(),

        "REVIEW":
            discord.Color.orange(),

        "HIGH":
            discord.Color.red(),
    }

    return colors.get(
        level,
        discord.Color.light_grey()
    )


def get_triage_icon(level):

    icons = {
        "MINIMAL": "🟢",
        "LOW": "🟡",
        "REVIEW": "🟠",
        "HIGH": "🔴",
    }

    return icons.get(
        level,
        "⚪"
    )


def is_zip_attachment(
    attachment
):

    return (
        Path(
            attachment.filename
        ).suffix.lower()
        == ".zip"
    )


# ============================================================
# URL EMBED
# ============================================================

def create_url_analysis_embed(
    result
):

    findings = result.get(
        "findings",
        []
    )

    if findings:

        findings_text = "\n".join(
            f"• {finding}"
            for finding in findings[:10]
        )

        if len(findings) > 10:
            findings_text += (
                f"\n• ... and "
                f"{len(findings) - 10} more"
            )

    else:

        findings_text = (
            "No suspicious indicators detected."
        )

    score = result.get(
        "score",
        0
    )

    if score >= 75:
        color = discord.Color.red()

    elif score >= 50:
        color = discord.Color.orange()

    elif score >= 25:
        color = discord.Color.yellow()

    else:
        color = discord.Color.green()

    embed = discord.Embed(
        title="IOCYRA URL Analysis",
        color=color
    )

    embed.add_field(
        name="Risk Score",
        value=f"**{score}/100**",
        inline=True
    )

    embed.add_field(
        name="Verdict",
        value=(
            f"**{result.get('verdict', 'Unknown')}**"
        ),
        inline=True
    )

    embed.add_field(
        name="URL",
        value=truncate(
            f"`{result.get('url', 'Unknown')}`"
        ),
        inline=False
    )

    embed.add_field(
        name="Findings",
        value=findings_text,
        inline=False
    )

    embed.set_footer(
        text="IOCYRA URL Analyzer"
    )

    return embed


# ============================================================
# FILE EMBED
# ============================================================

def create_file_analysis_embed(
    result
):

    file_info = result["file"]
    pe_info = result["pe"]
    static_analysis = result[
        "static_analysis"
    ]

    powershell = result.get(
        "powershell"
    )

    combinations = result.get(
        "behavioral_combinations",
        []
    )

    triage = result["triage"]

    level = triage["level"]

    embed = discord.Embed(
        title="IOCYRA File Analysis",
        color=get_triage_color(
            level
        )
    )

    embed.add_field(
        name="File",
        value=truncate(
            f"`{file_info['name']}`"
        ),
        inline=False
    )

    embed.add_field(
        name="Triage",
        value=(
            f"{get_triage_icon(level)} "
            f"**{level}**\n"
            f"Score: **{triage['score']}**"
        ),
        inline=True
    )

    embed.add_field(
        name="Type",
        value=(
            "PE executable"
            if pe_info["is_pe"]
            else "Non-PE file"
        ),
        inline=True
    )

    embed.add_field(
        name="Architecture",
        value=(
            pe_info["architecture"]
            or "Unknown"
        ),
        inline=True
    )

    embed.add_field(
        name="Size",
        value=format_file_size(
            file_info["size"]
        ),
        inline=True
    )

    embed.add_field(
        name="SHA-256",
        value=(
            f"`{file_info['sha256']}`"
        ),
        inline=False
    )

    counts = static_analysis[
        "counts"
    ]

    embed.add_field(
        name="Static Indicators",
        value=(
            f"🔴 High: **{counts['high']}**\n"
            f"🟠 Medium: **{counts['medium']}**\n"
            f"🟡 Low: **{counts['low']}**"
        ),
        inline=True
    )

    notable_findings = [
        indicator["category"]
        for indicator
        in static_analysis["indicators"]
        if indicator["confidence"]
        in {"HIGH", "MEDIUM"}
    ]

    if notable_findings:

        findings_text = "\n".join(
            f"• {finding}"
            for finding
            in notable_findings[:8]
        )

    else:

        findings_text = (
            "No medium or high-confidence "
            "static indicators."
        )

    embed.add_field(
        name="Notable Findings",
        value=truncate(
            findings_text
        ),
        inline=False
    )

    if powershell:

        ps_confidence = powershell.get(
            "confidence",
            "UNKNOWN"
        )

        ps_findings = powershell.get(
            "findings",
            []
        )

        ps_text = (
            f"Confidence: **{ps_confidence}**"
        )

        if ps_findings:

            ps_categories = [
                finding["category"]
                for finding
                in ps_findings
            ]

            ps_text += "\n" + "\n".join(
                f"• {category}"
                for category
                in ps_categories[:6]
            )

        embed.add_field(
            name="PowerShell",
            value=truncate(
                ps_text
            ),
            inline=False
        )

    if combinations:

        combination_text = "\n".join(
            f"• {combination['category']}"
            for combination
            in combinations[:8]
        )

    else:

        combination_text = (
            "None detected."
        )

    embed.add_field(
        name="Behavioral Combinations",
        value=truncate(
            combination_text
        ),
        inline=False
    )

    embed.set_footer(
        text=(
            "Static analysis only • "
            "A finding does not prove execution "
            "or maliciousness."
        )
    )

    return embed


# ============================================================
# ARCHIVE EMBED
# ============================================================

def create_archive_analysis_embed(
    result
):

    archive = result["archive"]
    files = result["files"]
    summary = result["summary"]

    # --------------------------------------------------------
    # Determine overall archive triage
    # --------------------------------------------------------

    analyzed_results = [
        file_result
        for file_result in files
        if "triage" in file_result
    ]

    levels = [
        file_result["triage"]["level"]
        for file_result in analyzed_results
    ]

    scores = [
        file_result["triage"]["score"]
        for file_result in analyzed_results
    ]

    if "HIGH" in levels:
        overall_level = "HIGH"

    elif "REVIEW" in levels:
        overall_level = "REVIEW"

    elif "LOW" in levels:
        overall_level = "LOW"

    else:
        overall_level = "MINIMAL"

    overall_score = max(
        scores,
        default=0
    )

    embed = discord.Embed(
        title="IOCYRA Archive Analysis",
        color=get_triage_color(
            overall_level
        )
    )

    # --------------------------------------------------------
    # Archive information
    # --------------------------------------------------------

    embed.add_field(
        name="Archive",
        value=truncate(
            f"`{archive['name']}`"
        ),
        inline=False
    )

    embed.add_field(
        name="Triage",
        value=(
            f"{get_triage_icon(overall_level)} "
            f"**{overall_level}**\n"
            f"Highest score: **{overall_score}**"
        ),
        inline=True
    )

    embed.add_field(
        name="Size",
        value=format_file_size(
            archive["size"]
        ),
        inline=True
    )

    embed.add_field(
        name="Contents",
        value=(
            f"Files: **{archive['file_count']}**\n"
            f"Analyzed: **{summary['analyzed']}**\n"
            f"Skipped: **{summary['skipped']}**"
        ),
        inline=True
    )

    # --------------------------------------------------------
    # Analyzed files
    # --------------------------------------------------------

    if analyzed_results:

        analyzed_text = []

        for file_result in analyzed_results[:8]:

            file_info = file_result[
                "file"
            ]

            triage = file_result[
                "triage"
            ]

            icon = get_triage_icon(
                triage["level"]
            )

            analyzed_text.append(
                f"{icon} `{file_info['name']}`\n"
                f"   {triage['level']} "
                f"(score {triage['score']})"
            )

        if len(analyzed_results) > 8:
            analyzed_text.append(
                f"... and "
                f"{len(analyzed_results) - 8} more"
            )

        analyzed_text = "\n".join(
            analyzed_text
        )

    else:

        analyzed_text = (
            "No supported PE files found."
        )

    embed.add_field(
        name="Analyzed Files",
        value=truncate(
            analyzed_text
        ),
        inline=False
    )

    # --------------------------------------------------------
    # Unsafe entries
    # --------------------------------------------------------

    unsafe_count = len(
        archive["unsafe_entries"]
    )

    if unsafe_count:

        embed.add_field(
            name="Archive Warnings",
            value=(
                f"⚠️ **{unsafe_count}** unsafe "
                "archive path(s) were skipped."
            ),
            inline=False
        )

    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    embed.set_footer(
        text=(
            "Archive contents were not executed • "
            "PE files were statically analyzed only."
        )
    )

    return embed


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

async def analyze_attachment(
    attachment
):

    if attachment.size > MAX_FILE_SIZE:

        raise ValueError(
            "That file is too large. "
            "Maximum supported upload size is "
            f"{format_file_size(MAX_FILE_SIZE)}."
        )

    suffix = Path(
        attachment.filename
    ).suffix

    fd, temp_path = tempfile.mkstemp(
        suffix=suffix
    )

    os.close(fd)

    try:

        await attachment.save(
            temp_path
        )

        if is_zip_attachment(
            attachment
        ):

            result = await asyncio.to_thread(
                analyze_archive,
                temp_path,
                attachment.filename
            )

            return (
                "archive",
                result
            )

        result = await asyncio.to_thread(
            analyze_file,
            temp_path
        )

        result["file"]["name"] = (
            attachment.filename
        )

        return (
            "file",
            result
        )

    finally:

        try:
            os.remove(
                temp_path
            )

        except OSError:
            pass


# ============================================================
# SEND ATTACHMENT ANALYSIS
# ============================================================

async def send_attachment_analysis(
    interaction,
    attachment
):

    await interaction.response.defer()

    try:

        analysis_type, result = (
            await analyze_attachment(
                attachment
            )
        )

        if analysis_type == "archive":

            embed = create_archive_analysis_embed(
                result
            )

        else:

            embed = create_file_analysis_embed(
                result
            )

        await interaction.followup.send(
            embed=embed
        )

    except ValueError as error:

        await interaction.followup.send(
            str(error)
        )

    except Exception as error:

        print(
            f"[IOCYRA] Attachment analysis error: "
            f"{error}"
        )

        await interaction.followup.send(
            "IOCYRA couldn't analyze that file."
        )


# ============================================================
# BOT EVENTS
# ============================================================

@bot.event
async def on_ready():

    await bot.tree.sync(
        guild=GUILD
    )

    print(
        f"Logged in as {bot.user}"
    )


# ============================================================
# /ANALYZE
# ============================================================

@bot.tree.command(
    name="analyze",
    description="Analyze a URL or file",
    guild=GUILD
)
@app_commands.describe(
    target="HTTP/HTTPS URL to analyze",
    file="File to analyze"
)
async def analyze_command(
    interaction: discord.Interaction,
    target: str | None = None,
    file: discord.Attachment | None = None
):

    if not target and not file:

        await interaction.response.send_message(
            "Give me a URL or attach a file to analyze."
        )

        return

    if target and file:

        await interaction.response.send_message(
            "Please provide either a URL or a file, "
            "not both."
        )

        return

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if target:

        target = target.strip()

        if not URL_PATTERN.fullmatch(
            target
        ):

            await interaction.response.send_message(
                "That doesn't look like a valid "
                "HTTP/HTTPS URL."
            )

            return

        await interaction.response.defer()

        try:

            result = await asyncio.to_thread(
                analyze_url,
                target
            )

            embed = create_url_analysis_embed(
                result
            )

            await interaction.followup.send(
                embed=embed
            )

        except Exception as error:

            print(
                f"[IOCYRA] URL analysis error: "
                f"{error}"
            )

            await interaction.followup.send(
                "IOCYRA couldn't analyze that URL."
            )

        return

    # --------------------------------------------------------
    # File / archive
    # --------------------------------------------------------

    await send_attachment_analysis(
        interaction,
        file
    )


# ============================================================
# ANALYZE MESSAGE
# ============================================================

@bot.tree.context_menu(
    name="Analyze Message",
    guild=GUILD
)
async def analyze_message(
    interaction: discord.Interaction,
    message: discord.Message
):

    # --------------------------------------------------------
    # URL first
    # --------------------------------------------------------

    url = extract_url(
        message.content
    )

    if url:

        await interaction.response.defer()

        try:

            result = await asyncio.to_thread(
                analyze_url,
                url
            )

            embed = create_url_analysis_embed(
                result
            )

            await interaction.followup.send(
                embed=embed
            )

        except Exception as error:

            print(
                f"[IOCYRA] URL analysis error: "
                f"{error}"
            )

            await interaction.followup.send(
                "IOCYRA couldn't analyze that URL."
            )

        return

    # --------------------------------------------------------
    # Attachment
    # --------------------------------------------------------

    if message.attachments:

        attachment = (
            message.attachments[0]
        )

        await send_attachment_analysis(
            interaction,
            attachment
        )

        return

    # --------------------------------------------------------
    # Nothing found
    # --------------------------------------------------------

    await interaction.response.send_message(
        "I couldn't find a URL or file to analyze "
        "in that message."
    )


# ============================================================
# PING
# ============================================================

@bot.command()
async def ping(ctx):

    await ctx.send(
        "IOCYRA is alive 👀"
    )


# ============================================================
# START BOT
# ============================================================

if not DISCORD_TOKEN:

    raise RuntimeError(
        "DISCORD_TOKEN is not set in the environment."
    )


bot.run(
    DISCORD_TOKEN
)