import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
import logging
from urllib.parse import urlparse
from sqlalchemy.exc import SQLAlchemyError
import tldextract


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("HISTORY_DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# urls
class URL(db.Model):
    __tablename__ = "urls"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, unique=True, nullable=False)
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)

# domain
class Domain(db.Model):
    __tablename__ = "domains"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String, unique=True, nullable=False)
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)

# threat_intel result
class ThreatIntelResult(db.Model):
    __tablename__ = "threat_intel_results"
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey("urls.id"), nullable=False)
    vt_safe = db.Column(db.Boolean)
    vt_malicious = db.Column(db.Integer)
    vt_undetected = db.Column(db.Integer)
    webrisk_safe = db.Column(db.Boolean)
    raw = db.Column(JSONB)
    last_checked_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)

# domain analyzer
class DomainAnalyzerResult(db.Model):
    __tablename__ = "domain_analyzer_results"
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id"), nullable=False)
    safe = db.Column(db.Boolean)
    malicious = db.Column(db.Integer)
    undetected = db.Column(db.Integer)
    raw = db.Column(JSONB)
    last_checked_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)

# content analyzer
class ContentAnalyzerResult(db.Model):
    __tablename__ = "content_analyzer_results"
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey("urls.id"), nullable=False)
    verdict = db.Column(db.Boolean)
    explanation = db.Column(db.Text)
    raw_ai = db.Column(db.Text)
    raw = db.Column(JSONB)
    last_checked_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)

# behavior actions
class BehaviorAction(db.Model):
    __tablename__ = "behavior_actions"
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey("urls.id"), nullable=False)
    actions_json = db.Column(JSONB)
    raw = db.Column(JSONB)
    last_checked_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)

# behavior summary
class BehaviorSummary(db.Model):
    __tablename__ = "behavior_summary"
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey("urls.id"), nullable=False)
    verdict = db.Column(db.Boolean)
    explanation = db.Column(db.Text)
    raw_ai = db.Column(db.Text)
    raw = db.Column(JSONB)
    last_checked_at = db.Column(db.DateTime)
    expire_at = db.Column(db.DateTime)


def get_or_create_url(url):
    record = URL.query.filter_by(url=url).first()
    if record:
        return record
    record = URL(url=url)
    db.session.add(record)
    db.session.commit()
    return record

def is_expired(record: URL):
    return record.expire_at and record.expire_at < datetime.utcnow()

def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    ext = tldextract.extract(host)
    if not ext.domain:
        raise ValueError(f"Cannot extract domain from URL: {url}")
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


@app.route("/check_history", methods=["POST"])
def check_history():
    data = request.get_json(force=True)

    service = data.get("service")
    url = data.get("url")

    if not service or not url:
        return jsonify({"cached": False, "error": "missing service or url"}), 400

    if service in ("threat_intel", "content_analyzer", "behavior_analyzer", "behavior_summary"):
        record = URL.query.filter_by(url=url).first()
        if not record or is_expired(record):
            return jsonify({"cached": False})

        if service == "threat_intel":
            r = ThreatIntelResult.query.filter_by(url_id=record.id).first()
        elif service == "content_analyzer":
            r = ContentAnalyzerResult.query.filter_by(url_id=record.id).first()
        elif service == "behavior_analyzer":
            r = BehaviorAction.query.filter_by(url_id=record.id).first()
        elif service == "behavior_summary":
            r = BehaviorSummary.query.filter_by(url_id=record.id).first()
        else:
            r = None

        if not r or not r.expire_at or r.expire_at < datetime.utcnow():
            return jsonify({"cached": False})

        return jsonify({"cached": True, "result": r.raw})


    elif service == "domain_analyzer":
        domain = extract_domain(url)
        if not domain:
            return jsonify({"cached": False}), 400

        domain_record = Domain.query.filter_by(domain=domain).first()
        if not domain_record:
            return jsonify({"cached": False}), 400

        r = DomainAnalyzerResult.query.filter_by(domain_id=domain_record.id).first()
        if not r or not r.expire_at or r.expire_at < datetime.utcnow():
            return jsonify({"cached": False})

        return jsonify({"cached": True, "result": r.raw})

    return jsonify({"cached": False, "error": "unknown service"}), 400


def parse_iso_datetime(s):
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        try:
            dt = datetime.strptime(s.split('.')[0], "%Y-%m-%dT%H:%M:%S")
            return dt
        except Exception:
            return None


@app.route("/update_history", methods=["POST"])
def update_history():
    payload = request.get_json(force=True)
    service = payload.get("service")
    url = payload.get("url")
    result_wrapper = payload.get("result") or payload.get("data") or payload

    if not service or not url or not result_wrapper:
        return jsonify({"status": "error", "error": "missing service, url or result"}), 400

    service_data = result_wrapper.get("data") if isinstance(result_wrapper, dict) and "data" in result_wrapper else result_wrapper

    try:
        url_record = get_or_create_url(url)
        url_record.last_checked_at = datetime.utcnow()
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.exception("Failed to get/create url")
        return jsonify({"status": "error", "error": "db_url_error", "detail": str(e)}), 500

    def bump_url_expire(new_dt):
        if not new_dt:
            return
        if new_dt.tzinfo:
            new_dt = new_dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        if not url_record.expire_at or new_dt > url_record.expire_at:
            url_record.expire_at = new_dt

    try:
        if service == "domain_analyzer":
            virustotal_domain = service_data.get("virustotal_domain", {}) if isinstance(service_data, dict) else {}
            domain_name = virustotal_domain.get("domain") or extract_domain(url)
            if not domain_name:
                return jsonify({"status": "error", "error": "cannot_extract_domain"}), 400

            domain_record = Domain.query.filter_by(domain=domain_name).first()
            if not domain_record:
                domain_record = Domain(domain=domain_name, first_seen_at=datetime.utcnow())
                db.session.add(domain_record)
                db.session.flush()

            domain_record.last_checked_at = parse_iso_datetime(
                virustotal_domain.get("last_checked_at")) or datetime.utcnow()
            domain_expire = parse_iso_datetime(virustotal_domain.get("expire_time"))
            if domain_expire:
                domain_record.expire_at = domain_expire
            db.session.add(domain_record)

            dar = DomainAnalyzerResult.query.filter_by(domain_id=domain_record.id).first()
            if not dar:
                dar = DomainAnalyzerResult(domain_id=domain_record.id)
                db.session.add(dar)

            dar.safe = service_data.get("safe")
            stats = virustotal_domain.get("stats", {})
            dar.malicious = stats.get("malicious", 0)
            dar.undetected = stats.get("undetected", 0)

            dar.raw = service_data

            dar.last_checked_at = domain_record.last_checked_at
            dar.expire_at = domain_expire

            bump_url_expire(domain_expire)

        elif service == "threat_intel":
            # service_data expected: {"url":..., "virustotal": {...}, "webrisk": {...}}
            vt = service_data.get("virustotal", {}) if isinstance(service_data, dict) else {}
            webrisk = service_data.get("webrisk", {}) if isinstance(service_data, dict) else {}

            url_record.last_checked_at = parse_iso_datetime(vt.get("checked_at")) or parse_iso_datetime(webrisk.get("checked_at")) or url_record.last_checked_at

            tir = ThreatIntelResult.query.filter_by(url_id=url_record.id).first()
            if not tir:
                tir = ThreatIntelResult(url_id=url_record.id)
                db.session.add(tir)

            tir.vt_safe = vt.get("safe")
            tir.vt_malicious = vt.get("stats", {}).get("malicious") if isinstance(vt.get("stats"), dict) else None
            tir.vt_undetected = vt.get("stats", {}).get("undetected") if isinstance(vt.get("stats"), dict) else None
            tir.webrisk_safe = webrisk.get("safe") if webrisk else None

            tir.raw = service_data
            tir.last_checked_at = parse_iso_datetime(vt.get("checked_at")) or parse_iso_datetime(webrisk.get("checked_at")) or datetime.utcnow()
            tir.expire_at = parse_iso_datetime(vt.get("expire_time")) or parse_iso_datetime(webrisk.get("expire_time"))

            bump_url_expire(tir.expire_at)

        elif service == "content_analyzer":
            # service_data expected: {"checked_at": "...", "expire_time":"...", "explanation": "...", "raw_ai": "...", "verdict": true}
            checked = parse_iso_datetime(service_data.get("checked_at"))
            expire = parse_iso_datetime(service_data.get("expire_time"))

            car = ContentAnalyzerResult.query.filter_by(url_id=url_record.id).first()
            if not car:
                car = ContentAnalyzerResult(url_id=url_record.id)
                db.session.add(car)

            car.verdict = service_data.get("verdict")
            car.explanation = service_data.get("explanation")

            car.raw_ai = service_data.get("raw_ai") or service_data.get("rawAI") or None
            car.raw = service_data
            car.last_checked_at = checked or datetime.utcnow()
            car.expire_at = expire

            bump_url_expire(car.expire_at)

        elif service == "behavior_analyzer":
            # service_data expected: {"results": [...], "status": "ok"}
            results = service_data.get("results") if isinstance(service_data, dict) else None
            checked = parse_iso_datetime(service_data.get("checked_at")) or datetime.utcnow()
            expire = parse_iso_datetime(service_data.get("expire_time"))

            ba = BehaviorAction.query.filter_by(url_id=url_record.id).first()
            if not ba:
                ba = BehaviorAction(url_id=url_record.id)
                db.session.add(ba)

            ba.actions_json = results if results is not None else service_data
            ba.raw = service_data
            ba.last_checked_at = checked
            ba.expire_at = expire

            bump_url_expire(ba.expire_at)

        elif service == "behavior_summary":
            checked = parse_iso_datetime(service_data.get("checked_at"))
            expire = parse_iso_datetime(service_data.get("expire_time"))

            bs = BehaviorSummary.query.filter_by(url_id=url_record.id).first()
            if not bs:
                bs = BehaviorSummary(url_id=url_record.id)
                db.session.add(bs)

            bs.verdict = service_data.get("verdict")
            bs.explanation = service_data.get("explanation")
            bs.raw_ai = service_data.get("raw_ai") or service_data.get("rawAI")
            bs.raw = service_data
            bs.last_checked_at = checked or datetime.utcnow()
            bs.expire_at = expire

            bump_url_expire(bs.expire_at)

        else:
            return jsonify({"status": "error", "error": f"unknown service {service}"}), 400

        if not url_record.first_seen_at:
            url_record.first_seen_at = datetime.utcnow()
        url_record.last_checked_at = datetime.utcnow()
        db.session.add(url_record)
        db.session.commit()

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.exception("DB error during update_history")
        return jsonify({"status": "error", "error": "db_error", "detail": str(e)}), 500
    except Exception as e:
        db.session.rollback()
        logger.exception("Unexpected error in update_history")
        return jsonify({"status": "error", "error": "internal_error", "detail": str(e)}), 500

    return jsonify({"status": "ok", "saved_for": service, "url_id": url_record.id})


@app.route("/delete_url", methods=["DELETE"])
def delete_url():
    data = request.get_json(force=True)
    url = data.get("url")

    if not url:
        return jsonify({"status": "error", "error": "missing url"}), 400

    try:
        url_record = URL.query.filter_by(url=url).first()
        if not url_record:
            return jsonify({"status": "error", "error": "url_not_found"}), 404

        url_id = url_record.id

        ThreatIntelResult.query.filter_by(url_id=url_id).delete()
        ContentAnalyzerResult.query.filter_by(url_id=url_id).delete()
        BehaviorAction.query.filter_by(url_id=url_id).delete()
        BehaviorSummary.query.filter_by(url_id=url_id).delete()

        db.session.delete(url_record)

        try:
            domain_name = extract_domain(url)
            domain_record = Domain.query.filter_by(domain=domain_name).first()

            if domain_record:
                other_urls_exist = (
                    db.session.query(URL)
                    .filter(URL.url.like(f"%{domain_name}%"))
                    .count()
                )

                if other_urls_exist == 0:
                    DomainAnalyzerResult.query.filter_by(domain_id=domain_record.id).delete()
                    db.session.delete(domain_record)

        except Exception:
            logger.warning(f"Domain cleanup failed for {url}")

        db.session.commit()

        return jsonify({
            "status": "ok",
            "deleted_url": url,
            "deleted_url_id": url_id
        })

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.exception("DB error during delete_url")
        return jsonify({"status": "error", "error": "db_error", "detail": str(e)}), 500

    except Exception as e:
        db.session.rollback()
        logger.exception("Unexpected error in delete_url")
        return jsonify({"status": "error", "error": "internal_error", "detail": str(e)}), 500



@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    host = os.getenv("HISTORY_SERVICE_HOST", "0.0.0.0")
    port = int(os.getenv("HISTORY_SERVICE_PORT", 8005))
    logger.info(f"Starting History Service on {host}:{port}")
    with app.app_context():
        db.create_all()
    app.run(host=host, port=port)
