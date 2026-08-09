/**
 * Global modal-backdrop safety-net
 * ป้องกัน backdrop ค้างบังหน้าจอทุกหน้าที่ extends base.html
 */
(function () {
    'use strict';

    // กันดับเบิลคลิกเปิด modal ซ้ำ (ต้นเหตุ backdrop ซ้อน)
    document.addEventListener('click', function (e) {
        var trigger = e.target.closest('[data-bs-toggle="modal"]');
        if (trigger && trigger.dataset.btaLocked === '1') {
            e.stopImmediatePropagation();
            e.preventDefault();
            return;
        }
        if (trigger) {
            trigger.dataset.btaLocked = '1';
            setTimeout(function () { delete trigger.dataset.btaLocked; }, 500);
        }
    }, true);

    // เคลียร์ backdrop/class ที่ค้าง หลัง modal ปิดสมบูรณ์
    document.addEventListener('hidden.bs.modal', function () {
        if (!document.querySelector('.modal.show')) {
            document.querySelectorAll('.modal-backdrop').forEach(function (el) {
                el.remove();
            });
            document.body.classList.remove('modal-open');
            document.body.style.removeProperty('overflow');
            document.body.style.removeProperty('padding-right');
        }
    });
})();