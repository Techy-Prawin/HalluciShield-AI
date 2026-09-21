import { pool } from '../config/db';
import { RuntimeEvent, CreateRuntimeEventInput } from './types';

export class RuntimeEventModel {
  static async create(input: CreateRuntimeEventInput): Promise<RuntimeEvent> {
    const query = `
      INSERT INTO runtime_events (
        repository_id, scan_id, patch_id, event_type, severity, stack_trace, payload, timestamp
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *;
    `;
    const values = [
      input.repository_id,
      input.scan_id || null,
      input.patch_id || null,
      input.event_type,
      input.severity || 'MEDIUM',
      input.stack_trace || null,
      JSON.stringify(input.payload || {}),
      input.timestamp ? input.timestamp.toISOString() : new Date().toISOString()
    ];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id: string): Promise<RuntimeEvent | null> {
    const { rows } = await pool.query('SELECT * FROM runtime_events WHERE id = $1', [id]);
    return rows[0] || null;
  }

  static async findByRepositoryId(repositoryId: string, limit = 100): Promise<RuntimeEvent[]> {
    const { rows } = await pool.query(
      'SELECT * FROM runtime_events WHERE repository_id = $1 ORDER BY timestamp DESC LIMIT $2',
      [repositoryId, limit]
    );
    return rows;
  }

  static async findByEventType(eventType: string, limit = 100): Promise<RuntimeEvent[]> {
    const { rows } = await pool.query(
      'SELECT * FROM runtime_events WHERE event_type = $1 ORDER BY timestamp DESC LIMIT $2',
      [eventType, limit]
    );
    return rows;
  }

  static async delete(id: string): Promise<boolean> {
    const { rowCount } = await pool.query('DELETE FROM runtime_events WHERE id = $1', [id]);
    return (rowCount ?? 0) > 0;
  }
}
